# freeSIEM Sentinel 0.2.2

- send an immediate heartbeat to freeSIEM Core whenever a pending task changes status
- report approve, deny, executing, completed, and failed states without waiting for the scheduled priority heartbeat
- keep the scheduled heartbeat fallback in place for reliability
