CREATE OR REPLACE VIEW closed_runs AS SELECT run_id FROM conn_events WHERE event_type='run_closed';

CREATE OR REPLACE VIEW connections AS
SELECT e.*, a.account_id, coalesce(auth_user, '') = '' AS missing_identity,
       min(event_time) OVER (PARTITION BY conn_id) AS first_seen,
       CASE
         WHEN event_type NOT IN ('start','snapshot') THEN event_type
         WHEN run_id IN (SELECT run_id FROM closed_runs) THEN 'interrupted'
         ELSE 'unfinished'
       END AS state
FROM conn_events e LEFT JOIN accounts a USING (inbound_tag,auth_user) WHERE event_type <> 'run_closed'
QUALIFY row_number() OVER (PARTITION BY conn_id ORDER BY seq DESC) = 1;

CREATE OR REPLACE VIEW dns_requests AS
SELECT e.*, a.account_id, coalesce(auth_user, '') = '' AS missing_identity,
       questions[1].Name AS qname, questions[1].Qtype AS qtype,
       min(event_time) OVER (PARTITION BY request_id) AS first_seen,
       CASE
         WHEN event_type <> 'start' THEN event_type
         WHEN run_id IN (SELECT run_id FROM closed_runs) THEN 'interrupted'
         ELSE 'unfinished'
       END AS state
FROM dns_events e LEFT JOIN accounts a USING (inbound_tag,auth_user)
QUALIFY row_number() OVER (PARTITION BY request_id ORDER BY (event_type='end') DESC,
                          (event_type='interrupted') DESC, event_time DESC)=1;

CREATE OR REPLACE VIEW daily_usage AS
WITH increments AS (
    SELECT event_time, inbound_tag, auth_user, coalesce(sniffed_domain,requested_host,routed_destination) AS domain,
           route_outbound, upload_bytes-lag(upload_bytes,1,0) OVER w AS up,
           download_bytes-lag(download_bytes,1,0) OVER w AS down
    FROM conn_events WHERE event_type <> 'run_closed' WINDOW w AS (PARTITION BY conn_id ORDER BY seq)
    UNION ALL
    SELECT first_seen, inbound_tag, auth_user, qname, NULL, upload_bytes, 0 FROM dns_requests
    UNION ALL
    SELECT event_time, inbound_tag, auth_user, qname, NULL, 0, download_bytes FROM dns_requests
)
SELECT epoch_ms(event_time)::DATE AS utc_day, inbound_tag, auth_user, a.account_id, domain, route_outbound,
       sum(up) AS upload_bytes, sum(down) AS download_bytes
FROM increments LEFT JOIN accounts a USING(inbound_tag,auth_user)
GROUP BY ALL;
