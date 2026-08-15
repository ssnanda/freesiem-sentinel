<?php
/**
 * Minimal, dependency-free S3-compatible client (AWS Signature Version 4).
 *
 * Works against any S3-API-compatible server (MinIO, RustFS, AWS S3, etc.) --
 * only the endpoint/region/credentials/path-style flag change between them.
 * No Composer/vendor dependency, so this hand-rolls the handful of SigV4
 * request shapes it needs instead of pulling in the full AWS SDK. Adapted
 * from AJCore's storage module (ajcore/modules/storage/class-ajcore-s3-client.php).
 */

if (!defined('ABSPATH')) {
	exit;
}

if ( ! class_exists( 'FreeSIEM_Sentinel_S3_Client' ) ) {

	class FreeSIEM_Sentinel_S3_Client {

		private $endpoint;
		private $region;
		private $access_key;
		private $secret_key;
		private $bucket;
		private $path_style;

		/**
		 * @param array $args {
		 *     @type string $endpoint   Base URL, e.g. https://files.ncllcagents.com
		 *     @type string $region     e.g. us-east-1 (MinIO/RustFS accept any string)
		 *     @type string $access_key
		 *     @type string $secret_key
		 *     @type string $bucket     Optional — not required for list_buckets().
		 *     @type bool   $path_style Default true (required for MinIO/RustFS behind a
		 *                              custom domain with no wildcard DNS). Set false for
		 *                              virtual-hosted-style addressing (typical on AWS S3).
		 * }
		 */
		public function __construct( $args ) {
			$args = wp_parse_args(
				$args,
				array(
					'endpoint'   => '',
					'region'     => 'us-east-1',
					'access_key' => '',
					'secret_key' => '',
					'bucket'     => '',
					'path_style' => true,
				)
			);

			$this->endpoint   = untrailingslashit( trim( (string) $args['endpoint'] ) );
			$this->region     = (string) $args['region'];
			$this->access_key = (string) $args['access_key'];
			$this->secret_key = (string) $args['secret_key'];
			$this->bucket     = (string) $args['bucket'];
			$this->path_style = (bool) $args['path_style'];
		}

		public function is_configured() {
			return '' !== $this->endpoint && '' !== $this->access_key && '' !== $this->secret_key;
		}

		/**
		 * GET / (service-level ListBuckets). Returns array of bucket names, or WP_Error.
		 */
		public function list_buckets() {
			$response = $this->request( 'GET', '/', '', array(), '' );
			if ( is_wp_error( $response ) ) {
				return $response;
			}

			$xml = $this->parse_xml( wp_remote_retrieve_body( $response ) );
			if ( is_wp_error( $xml ) ) {
				return $xml;
			}

			$buckets = array();
			if ( isset( $xml->Buckets->Bucket ) ) {
				foreach ( $xml->Buckets->Bucket as $bucket ) {
					$buckets[] = (string) $bucket->Name;
				}
			}

			return $buckets;
		}

		/**
		 * PUT an object. $body is the raw file contents (kept in memory — fine for the
		 * document-sized files this plugin handles, not intended for multi-GB uploads).
		 */
		public function put_object( $key, $body, $content_type = 'application/octet-stream' ) {
			$headers = array( 'content-type' => $content_type );
			return $this->request( 'PUT', $this->object_path( $key ), '', $headers, $body );
		}

		/**
		 * GET an object's raw bytes. Used only as a fallback proxy path; normal downloads
		 * should redirect the browser to presigned_url() instead of streaming through PHP.
		 */
		public function get_object( $key ) {
			$response = $this->request( 'GET', $this->object_path( $key ), '', array(), '' );
			if ( is_wp_error( $response ) ) {
				return $response;
			}
			return array(
				'body'         => wp_remote_retrieve_body( $response ),
				'content_type' => wp_remote_retrieve_header( $response, 'content-type' ),
			);
		}

		public function head_object( $key ) {
			$response = $this->request( 'HEAD', $this->object_path( $key ), '', array(), '' );
			if ( is_wp_error( $response ) ) {
				return $response;
			}
			$code = wp_remote_retrieve_response_code( $response );
			if ( 404 === (int) $code ) {
				return false;
			}
			return array(
				'content_length' => (int) wp_remote_retrieve_header( $response, 'content-length' ),
				'content_type'   => wp_remote_retrieve_header( $response, 'content-type' ),
				'etag'           => trim( (string) wp_remote_retrieve_header( $response, 'etag' ), '"' ),
			);
		}

		public function delete_object( $key ) {
			return $this->request( 'DELETE', $this->object_path( $key ), '', array(), '' );
		}

		/**
		 * Query-string-signed (presigned) URL — no Authorization header needed by the
		 * eventual requester, so it can be handed straight to a browser as a redirect
		 * target for time-limited direct downloads.
		 */
		public function presigned_url( $key, $expires_seconds = 300, $method = 'GET' ) {
			$host          = $this->host_for_request();
			$path          = $this->object_path( $key );
			$amz_date      = gmdate( 'Ymd\THis\Z' );
			$short_date    = gmdate( 'Ymd' );
			$scope         = "{$short_date}/{$this->region}/s3/aws4_request";
			$credential    = $this->access_key . '/' . $scope;

			$query_params = array(
				'X-Amz-Algorithm'     => 'AWS4-HMAC-SHA256',
				'X-Amz-Credential'    => $credential,
				'X-Amz-Date'          => $amz_date,
				'X-Amz-Expires'       => (string) max( 1, (int) $expires_seconds ),
				'X-Amz-SignedHeaders' => 'host',
			);

			$canonical_query = $this->canonical_query_string( $query_params );
			$canonical_headers = 'host:' . $host . "\n";
			$canonical_request = implode(
				"\n",
				array(
					strtoupper( $method ),
					$this->encode_uri_path( $path ),
					$canonical_query,
					$canonical_headers,
					'host',
					'UNSIGNED-PAYLOAD',
				)
			);

			$string_to_sign = implode(
				"\n",
				array(
					'AWS4-HMAC-SHA256',
					$amz_date,
					$scope,
					hash( 'sha256', $canonical_request ),
				)
			);

			$signing_key = $this->signing_key( $short_date );
			$signature   = hash_hmac( 'sha256', $string_to_sign, $signing_key );

			$url = $this->base_url_for_request() . $this->encode_uri_path( $path ) . '?' . $canonical_query . '&X-Amz-Signature=' . $signature;

			return $url;
		}

		// -----------------------------------------------------------------
		// Internals
		// -----------------------------------------------------------------

		private function object_path( $key ) {
			$key = ltrim( (string) $key, '/' );
			return $this->path_style ? '/' . $this->bucket . '/' . $key : '/' . $key;
		}

		private function host_for_request() {
			$parsed = wp_parse_url( $this->endpoint );
			$host   = isset( $parsed['host'] ) ? $parsed['host'] : '';
			if ( ! $this->path_style && '' !== $this->bucket ) {
				$host = $this->bucket . '.' . $host;
			}
			return $host;
		}

		private function base_url_for_request() {
			$parsed = wp_parse_url( $this->endpoint );
			$scheme = isset( $parsed['scheme'] ) ? $parsed['scheme'] : 'https';
			return $scheme . '://' . $this->host_for_request();
		}

		private function encode_uri_path( $path ) {
			$segments = explode( '/', $path );
			foreach ( $segments as &$segment ) {
				$segment = rawurlencode( $segment );
			}
			return implode( '/', $segments );
		}

		private function canonical_query_string( array $params ) {
			ksort( $params );
			$pairs = array();
			foreach ( $params as $k => $v ) {
				$pairs[] = rawurlencode( $k ) . '=' . rawurlencode( $v );
			}
			return implode( '&', $pairs );
		}

		private function signing_key( $short_date ) {
			$k_date    = hash_hmac( 'sha256', $short_date, 'AWS4' . $this->secret_key, true );
			$k_region  = hash_hmac( 'sha256', $this->region, $k_date, true );
			$k_service = hash_hmac( 'sha256', 's3', $k_region, true );
			return hash_hmac( 'sha256', 'aws4_request', $k_service, true );
		}

		private function parse_xml( $body ) {
			if ( '' === (string) $body ) {
				return new WP_Error( 'freesiem_sentinel_s3_empty_response', __( 'Empty response from storage server.', 'freesiem-sentinel' ) );
			}
			libxml_use_internal_errors( true );
			$xml = simplexml_load_string( $body );
			libxml_use_internal_errors( false );
			if ( false === $xml ) {
				return new WP_Error( 'freesiem_sentinel_s3_bad_xml', __( 'Storage server returned an unreadable response.', 'freesiem-sentinel' ) );
			}
			return $xml;
		}

		/**
		 * Signs and sends one request via wp_remote_request().
		 *
		 * @param string $path        Already-decoded path (bucket/key or empty for service ops).
		 * @param string $query       Raw (unsigned use-case) query string, usually ''.
		 * @param array  $extra_headers Lowercase header-name => value, merged into the signed set.
		 * @param string $body        Raw request body (empty string for GET/HEAD/DELETE).
		 */
		private function request( $method, $path, $query, $extra_headers, $body ) {
			if ( ! $this->is_configured() ) {
				return new WP_Error( 'freesiem_sentinel_s3_not_configured', __( 'Storage is not configured.', 'freesiem-sentinel' ) );
			}

			$method       = strtoupper( $method );
			$host         = $this->host_for_request();
			$amz_date     = gmdate( 'Ymd\THis\Z' );
			$short_date   = gmdate( 'Ymd' );
			$scope        = "{$short_date}/{$this->region}/s3/aws4_request";
			$payload_hash = hash( 'sha256', $body );

			$headers = array_merge(
				$extra_headers,
				array(
					'host'                 => $host,
					'x-amz-date'           => $amz_date,
					'x-amz-content-sha256' => $payload_hash,
				)
			);
			ksort( $headers );

			$canonical_headers = '';
			$signed_header_names = array();
			foreach ( $headers as $name => $value ) {
				$canonical_headers   .= $name . ':' . trim( $value ) . "\n";
				$signed_header_names[] = $name;
			}
			$signed_headers = implode( ';', $signed_header_names );

			$canonical_request = implode(
				"\n",
				array(
					$method,
					$this->encode_uri_path( $path ),
					(string) $query,
					$canonical_headers,
					$signed_headers,
					$payload_hash,
				)
			);

			$string_to_sign = implode(
				"\n",
				array(
					'AWS4-HMAC-SHA256',
					$amz_date,
					$scope,
					hash( 'sha256', $canonical_request ),
				)
			);

			$signing_key = $this->signing_key( $short_date );
			$signature   = hash_hmac( 'sha256', $string_to_sign, $signing_key );

			$authorization = sprintf(
				'AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s',
				$this->access_key,
				$scope,
				$signed_headers,
				$signature
			);

			$request_headers = $extra_headers;
			$request_headers['x-amz-date']           = $amz_date;
			$request_headers['x-amz-content-sha256'] = $payload_hash;
			$request_headers['authorization']        = $authorization;

			$url = $this->base_url_for_request() . $this->encode_uri_path( $path );
			if ( '' !== (string) $query ) {
				$url .= '?' . $query;
			}

			$response = wp_remote_request(
				$url,
				array(
					'method'    => $method,
					'headers'   => $request_headers,
					'body'      => ( '' === $body ) ? null : $body,
					'timeout'   => 30,
					'sslverify' => true,
				)
			);

			if ( is_wp_error( $response ) ) {
				return $response;
			}

			$code = (int) wp_remote_retrieve_response_code( $response );
			if ( $code >= 200 && $code < 300 ) {
				return $response;
			}
			if ( 'HEAD' === $method && 404 === $code ) {
				return $response; // Caller (head_object) interprets 404 itself.
			}

			return new WP_Error(
				'freesiem_sentinel_s3_http_error',
				sprintf(
					/* translators: 1: HTTP status code, 2: response body excerpt */
					__( 'Storage server returned HTTP %1$s: %2$s', 'freesiem-sentinel' ),
					$code,
					substr( wp_strip_all_tags( wp_remote_retrieve_body( $response ) ), 0, 300 )
				),
				array( 'status' => $code )
			);
		}
	}
}
