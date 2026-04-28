--
-- PostgreSQL database dump
--

\restrict hVxxbJ88431bMvbN34eObOQIRYAweWOrUaYP5j1xGyUw7nfhcRy87uCrgrTPKWB

-- Dumped from database version 17.9 (Ubuntu 17.9-1.pgdg24.04+1)
-- Dumped by pg_dump version 17.9 (Ubuntu 17.9-1.pgdg24.04+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: adversary_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.adversary_profiles (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    actor_name character varying(256),
    actor_type character varying(64),
    origin character varying(128),
    motivation character varying(128),
    sophistication character varying(32),
    confidence double precision,
    threat_level character varying(16),
    active_since character varying(32),
    targets text,
    ttps text,
    summary text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: agent_api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_api_keys (
    id integer NOT NULL,
    user_id integer NOT NULL,
    label character varying(128) NOT NULL,
    key_prefix character varying(20) NOT NULL,
    key_hash character varying(255) NOT NULL,
    scope character varying(64) NOT NULL,
    permissions json,
    enabled boolean NOT NULL,
    revoked_at timestamp with time zone,
    revoked_reason character varying(256),
    last_used_at timestamp with time zone,
    last_used_ip character varying(64),
    use_count integer,
    created_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone,
    node_meta json
);


--
-- Name: agent_api_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.agent_api_keys_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: agent_api_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.agent_api_keys_id_seq OWNED BY public.agent_api_keys.id;


--
-- Name: agent_devices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_devices (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    hostname character varying(256),
    platform character varying(64),
    ip_address character varying(64),
    agent_version character varying(32),
    first_seen timestamp without time zone,
    last_seen timestamp without time zone,
    status character varying(16)
);


--
-- Name: agent_scan_submissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_scan_submissions (
    id integer NOT NULL,
    user_id integer NOT NULL,
    scan_id character varying(256) NOT NULL,
    real_scan_id character varying(64) NOT NULL,
    agent_key_id integer,
    ingested_at timestamp with time zone NOT NULL
);


--
-- Name: agent_scan_submissions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.agent_scan_submissions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: agent_scan_submissions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.agent_scan_submissions_id_seq OWNED BY public.agent_scan_submissions.id;


--
-- Name: agent_telemetry; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_telemetry (
    id character varying(64) NOT NULL,
    agent_id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    collected_at timestamp without time zone,
    cpu_percent double precision,
    cpu_count integer,
    mem_total_gb double precision,
    mem_used_gb double precision,
    mem_percent double precision,
    disk_total_gb double precision,
    disk_used_gb double precision,
    disk_percent double precision,
    processes_json text,
    connections_json text,
    disks_json text
);


--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);


--
-- Name: ap_analyses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ap_analyses (
    id integer NOT NULL,
    name character varying(200) NOT NULL,
    scope character varying(200),
    total_paths integer,
    critical_paths integer,
    max_depth integer,
    created_by integer,
    created_at timestamp without time zone
);


--
-- Name: ap_analyses_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ap_analyses_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ap_analyses_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ap_analyses_id_seq OWNED BY public.ap_analyses.id;


--
-- Name: ap_paths; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ap_paths (
    id integer NOT NULL,
    analysis_id integer NOT NULL,
    entry_point character varying(200) NOT NULL,
    target character varying(200) NOT NULL,
    severity character varying(20),
    hops integer,
    chain text,
    techniques text,
    likelihood integer,
    impact character varying(200),
    blocked boolean,
    created_at timestamp without time zone
);


--
-- Name: ap_paths_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ap_paths_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ap_paths_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ap_paths_id_seq OWNED BY public.ap_paths.id;


--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_keys (
    id integer NOT NULL,
    user_id integer NOT NULL,
    key_hash character varying(255) NOT NULL,
    name character varying(255),
    last_used timestamp without time zone,
    created_at timestamp without time zone,
    is_active boolean
);


--
-- Name: api_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.api_keys_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: api_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.api_keys_id_seq OWNED BY public.api_keys.id;


--
-- Name: apm_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.apm_reports (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    service_name character varying(256),
    environment character varying(64),
    health_score double precision,
    avg_latency_ms double precision,
    p99_latency_ms double precision,
    throughput_rps double precision,
    error_rate_pct double precision,
    apdex_score double precision,
    issues integer,
    summary text,
    services_data text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: arch_builder_components; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.arch_builder_components (
    id character varying(64) NOT NULL,
    design_id character varying(64) NOT NULL,
    layer character varying(64),
    component character varying(256),
    service character varying(256),
    purpose text,
    security_note text,
    iac_snippet text,
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: arch_builder_designs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.arch_builder_designs (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    title character varying(256),
    cloud_provider character varying(32),
    arch_type character varying(64),
    security_score double precision,
    summary text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: as_endpoints; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.as_endpoints (
    id integer NOT NULL,
    path character varying(500) NOT NULL,
    method character varying(10) NOT NULL,
    service character varying(200),
    version character varying(20),
    auth_type character varying(50),
    authenticated boolean,
    rate_limited boolean,
    encrypted boolean,
    has_cors boolean,
    cors_wildcard boolean,
    sensitive_data boolean,
    deprecated boolean,
    risk_score integer,
    finding_count integer,
    last_tested timestamp without time zone,
    created_at timestamp without time zone
);


--
-- Name: as_endpoints_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.as_endpoints_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: as_endpoints_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.as_endpoints_id_seq OWNED BY public.as_endpoints.id;


--
-- Name: as_findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.as_findings (
    id integer NOT NULL,
    endpoint_id integer NOT NULL,
    finding_type character varying(100) NOT NULL,
    severity character varying(20),
    owasp_id character varying(20),
    title character varying(300) NOT NULL,
    description text,
    evidence text,
    remediation text,
    status character varying(30),
    created_at timestamp without time zone
);


--
-- Name: as_findings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.as_findings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: as_findings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.as_findings_id_seq OWNED BY public.as_findings.id;


--
-- Name: as_scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.as_scans (
    id integer NOT NULL,
    endpoints_scanned integer,
    findings_found integer,
    critical_count integer,
    duration_sec integer,
    created_at timestamp without time zone
);


--
-- Name: as_scans_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.as_scans_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: as_scans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.as_scans_id_seq OWNED BY public.as_scans.id;


--
-- Name: ask_usage_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ask_usage_log (
    id integer NOT NULL,
    user_id integer NOT NULL,
    date date NOT NULL,
    query_count integer NOT NULL,
    total_input_tokens integer NOT NULL,
    total_output_tokens integer NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: ask_usage_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ask_usage_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ask_usage_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ask_usage_log_id_seq OWNED BY public.ask_usage_log.id;


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    id character varying(36) NOT NULL,
    user_id integer,
    action character varying(100) NOT NULL,
    resource character varying(100),
    ip_address character varying(45),
    user_agent text,
    "timestamp" timestamp without time zone,
    status character varying(20)
);


--
-- Name: ba_anomalies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ba_anomalies (
    id integer NOT NULL,
    baseline_id integer NOT NULL,
    entity_name character varying(200) NOT NULL,
    anomaly_type character varying(100) NOT NULL,
    severity character varying(20),
    title character varying(300) NOT NULL,
    description text,
    deviation double precision,
    observed text,
    expected text,
    mitre_id character varying(50),
    status character varying(30),
    created_at timestamp without time zone,
    resolved_at timestamp without time zone
);


--
-- Name: ba_anomalies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ba_anomalies_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ba_anomalies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ba_anomalies_id_seq OWNED BY public.ba_anomalies.id;


--
-- Name: ba_baselines; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ba_baselines (
    id integer NOT NULL,
    entity_id character varying(200) NOT NULL,
    entity_type character varying(50) NOT NULL,
    entity_name character varying(200) NOT NULL,
    baseline text,
    confidence integer,
    risk_score integer,
    anomaly_count integer,
    last_updated timestamp without time zone,
    created_at timestamp without time zone
);


--
-- Name: ba_baselines_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ba_baselines_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ba_baselines_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ba_baselines_id_seq OWNED BY public.ba_baselines.id;


--
-- Name: ba_patterns; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ba_patterns (
    id integer NOT NULL,
    baseline_id integer NOT NULL,
    entity_name character varying(200) NOT NULL,
    hour integer NOT NULL,
    day_of_week integer NOT NULL,
    metrics text,
    recorded_at timestamp without time zone
);


--
-- Name: ba_patterns_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ba_patterns_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ba_patterns_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ba_patterns_id_seq OWNED BY public.ba_patterns.id;


--
-- Name: ca_assessments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ca_assessments (
    id integer NOT NULL,
    framework_id integer NOT NULL,
    score integer,
    passed integer,
    failed integer,
    partial integer,
    triggered_by character varying(100),
    created_at timestamp without time zone
);


--
-- Name: ca_assessments_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ca_assessments_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ca_assessments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ca_assessments_id_seq OWNED BY public.ca_assessments.id;


--
-- Name: ca_controls; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ca_controls (
    id integer NOT NULL,
    framework_id integer NOT NULL,
    control_id character varying(50) NOT NULL,
    title character varying(300) NOT NULL,
    description text,
    category character varying(100),
    status character varying(30),
    evidence text,
    gap text,
    remediation text,
    severity character varying(20),
    automated boolean,
    last_tested timestamp without time zone
);


--
-- Name: ca_controls_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ca_controls_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ca_controls_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ca_controls_id_seq OWNED BY public.ca_controls.id;


--
-- Name: ca_frameworks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ca_frameworks (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    version character varying(50),
    description text,
    total_controls integer,
    passed integer,
    failed integer,
    partial integer,
    score integer,
    last_assessed timestamp without time zone,
    created_at timestamp without time zone
);


--
-- Name: ca_frameworks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ca_frameworks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ca_frameworks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ca_frameworks_id_seq OWNED BY public.ca_frameworks.id;


--
-- Name: calendar_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_events (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    title character varying(256) NOT NULL,
    description text,
    event_type character varying(64),
    start_date timestamp without time zone NOT NULL,
    end_date timestamp without time zone,
    all_day boolean,
    status character varying(32),
    priority character varying(16),
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: central_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.central_events (
    id integer NOT NULL,
    source_module character varying(64) NOT NULL,
    source_table character varying(64) NOT NULL,
    source_row_id character varying(64) NOT NULL,
    event_type character varying(128) NOT NULL,
    severity character varying(16) NOT NULL,
    user_id integer,
    entity character varying(256),
    entity_type character varying(32),
    title character varying(512),
    description text,
    mitre_techniques json,
    risk_score integer,
    payload json,
    node_meta json,
    created_at timestamp without time zone NOT NULL
);


--
-- Name: central_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.central_events_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: central_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.central_events_id_seq OWNED BY public.central_events.id;


--
-- Name: cloud_accounts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cloud_accounts (
    id integer NOT NULL,
    name character varying(200) NOT NULL,
    provider character varying(50) NOT NULL,
    account_id character varying(200),
    region character varying(100),
    status character varying(30),
    asset_count integer,
    finding_count integer,
    last_scan timestamp without time zone,
    created_by integer,
    created_at timestamp without time zone
);


--
-- Name: cloud_accounts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cloud_accounts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cloud_accounts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cloud_accounts_id_seq OWNED BY public.cloud_accounts.id;


--
-- Name: cloud_assets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cloud_assets (
    id integer NOT NULL,
    account_id integer NOT NULL,
    asset_id character varying(200) NOT NULL,
    name character varying(200),
    asset_type character varying(50) NOT NULL,
    provider character varying(50) NOT NULL,
    region character varying(100),
    ip_address character varying(100),
    tags text,
    risk_score integer,
    public boolean,
    encrypted boolean,
    created_at timestamp without time zone
);


--
-- Name: cloud_assets_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cloud_assets_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cloud_assets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cloud_assets_id_seq OWNED BY public.cloud_assets.id;


--
-- Name: cloud_dashboard_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cloud_dashboard_snapshots (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    overall_score double precision,
    aws_score double precision,
    azure_score double precision,
    gcp_score double precision,
    total_resources integer,
    exposed_resources integer,
    critical_findings integer,
    high_findings integer,
    medium_findings integer,
    compliance_score double precision,
    trend_data text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: cloud_findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cloud_findings (
    id integer NOT NULL,
    account_id integer,
    asset_id integer,
    provider character varying(50) NOT NULL,
    finding_type character varying(100) NOT NULL,
    severity character varying(20) NOT NULL,
    title character varying(500) NOT NULL,
    description text,
    resource character varying(300),
    remediation text,
    mitre_id character varying(50),
    created_at timestamp without time zone
);


--
-- Name: cloud_findings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cloud_findings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cloud_findings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cloud_findings_id_seq OWNED BY public.cloud_findings.id;


--
-- Name: cloud_hardener_findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cloud_hardener_findings (
    id character varying(64) NOT NULL,
    scan_id character varying(64) NOT NULL,
    check_id character varying(32),
    category character varying(64),
    title character varying(256),
    status character varying(16),
    severity character varying(16),
    description text,
    remediation text,
    cis_ref character varying(64),
    auto_fix character varying(256),
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: cloud_hardener_scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cloud_hardener_scans (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    cloud_provider character varying(32),
    environment character varying(64),
    risk_score double precision,
    severity character varying(16),
    total_checks integer,
    passed integer,
    failed integer,
    summary text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: cloud_runtime_findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cloud_runtime_findings (
    id character varying(64) NOT NULL,
    scan_id character varying(64) NOT NULL,
    category character varying(64),
    title character varying(256),
    severity character varying(16),
    description text,
    resource character varying(256),
    remediation text,
    wiz_ref character varying(64),
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: cloud_runtime_scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cloud_runtime_scans (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    cloud_provider character varying(32),
    environment character varying(64),
    risk_score double precision,
    severity character varying(16),
    total_findings integer,
    critical_count integer,
    summary text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: code_findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.code_findings (
    id character varying(64) NOT NULL,
    scan_id character varying(64) NOT NULL,
    engine character varying(32),
    severity character varying(16),
    category character varying(64),
    title character varying(256),
    description text,
    file_path character varying(512),
    line_number integer,
    recommendation text,
    cwe_id character varying(32),
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: code_sbom; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.code_sbom (
    id character varying(64) NOT NULL,
    scan_id character varying(64) NOT NULL,
    component character varying(256),
    version character varying(64),
    ecosystem character varying(32),
    license character varying(128),
    is_vulnerable integer,
    vuln_summary text,
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: code_scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.code_scans (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    target_type character varying(32),
    target_name character varying(256),
    status character varying(32),
    risk_score double precision,
    total_findings integer,
    created_at timestamp without time zone,
    completed_at timestamp without time zone,
    node_meta text
);


--
-- Name: compliance_assessments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compliance_assessments (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    framework character varying(64),
    organisation character varying(256),
    overall_score double precision,
    passed integer,
    failed integer,
    partial integer,
    critical_gaps integer,
    status character varying(32),
    summary text,
    controls text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: compliance_fabric_controls; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compliance_fabric_controls (
    id character varying(64) NOT NULL,
    report_id character varying(64) NOT NULL,
    control_id character varying(32),
    title character varying(256),
    status character varying(16),
    severity character varying(16),
    description text,
    remediation text,
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: compliance_fabric_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compliance_fabric_reports (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    framework character varying(64),
    score double precision,
    status character varying(32),
    total_controls integer,
    passed integer,
    failed integer,
    partial integer,
    summary text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: compliance_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compliance_results (
    id integer NOT NULL,
    user_id integer NOT NULL,
    scan_id integer NOT NULL,
    framework character varying(50) NOT NULL,
    score integer NOT NULL,
    total integer NOT NULL,
    controls json,
    created_at timestamp without time zone
);


--
-- Name: compliance_results_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.compliance_results_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: compliance_results_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.compliance_results_id_seq OWNED BY public.compliance_results.id;


--
-- Name: cs_recommendations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cs_recommendations (
    id integer NOT NULL,
    resource_id integer NOT NULL,
    category character varying(50) NOT NULL,
    priority character varying(20),
    title character varying(300) NOT NULL,
    description text,
    action text,
    monthly_saving double precision,
    security_gain character varying(100),
    effort character varying(20),
    status character varying(30),
    created_at timestamp without time zone
);


--
-- Name: cs_recommendations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cs_recommendations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cs_recommendations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cs_recommendations_id_seq OWNED BY public.cs_recommendations.id;


--
-- Name: cs_resources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cs_resources (
    id integer NOT NULL,
    name character varying(200) NOT NULL,
    resource_type character varying(50) NOT NULL,
    cloud_provider character varying(50) NOT NULL,
    region character varying(100),
    monthly_cost double precision,
    optimised_cost double precision,
    waste_pct integer,
    security_score integer,
    security_issues integer,
    status character varying(30),
    tags text,
    created_at timestamp without time zone
);


--
-- Name: cs_resources_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cs_resources_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cs_resources_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cs_resources_id_seq OWNED BY public.cs_resources.id;


--
-- Name: cve_sync_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cve_sync_logs (
    id integer NOT NULL,
    started_at timestamp without time zone,
    finished_at timestamp without time zone,
    cves_added integer,
    cves_updated integer,
    status character varying(32),
    error text,
    source character varying(64)
);


--
-- Name: cve_sync_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cve_sync_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cve_sync_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cve_sync_logs_id_seq OWNED BY public.cve_sync_logs.id;


--
-- Name: dd_baselines; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dd_baselines (
    id integer NOT NULL,
    identity_name character varying(200) NOT NULL,
    identity_type character varying(50) NOT NULL,
    provider character varying(50) NOT NULL,
    environment character varying(50),
    permissions text,
    permission_count integer,
    drift_score integer,
    drift_count integer,
    status character varying(30),
    last_scanned timestamp without time zone,
    baseline_set_at timestamp without time zone,
    created_at timestamp without time zone
);


--
-- Name: dd_baselines_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dd_baselines_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dd_baselines_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dd_baselines_id_seq OWNED BY public.dd_baselines.id;


--
-- Name: dd_drifts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dd_drifts (
    id integer NOT NULL,
    baseline_id integer NOT NULL,
    identity_name character varying(200) NOT NULL,
    drift_type character varying(100) NOT NULL,
    severity character varying(20),
    title character varying(300) NOT NULL,
    description text,
    old_value text,
    new_value text,
    remediation text,
    regulation character varying(200),
    status character varying(30),
    detected_at timestamp without time zone,
    resolved_at timestamp without time zone
);


--
-- Name: dd_drifts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dd_drifts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dd_drifts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dd_drifts_id_seq OWNED BY public.dd_drifts.id;


--
-- Name: dd_scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dd_scans (
    id integer NOT NULL,
    identities_scanned integer,
    drifts_found integer,
    critical_drifts integer,
    duration_sec integer,
    created_at timestamp without time zone
);


--
-- Name: dd_scans_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dd_scans_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dd_scans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dd_scans_id_seq OWNED BY public.dd_scans.id;


--
-- Name: defense_actions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.defense_actions (
    id integer NOT NULL,
    playbook_id integer,
    playbook_name character varying(200),
    action_type character varying(100) NOT NULL,
    target character varying(200),
    status character varying(20),
    reason text,
    outcome text,
    triggered_by character varying(100),
    created_at timestamp without time zone
);


--
-- Name: defense_actions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.defense_actions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: defense_actions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.defense_actions_id_seq OWNED BY public.defense_actions.id;


--
-- Name: defense_mesh_pillars; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.defense_mesh_pillars (
    id character varying(64) NOT NULL,
    report_id character varying(64) NOT NULL,
    pillar_name character varying(128),
    score double precision,
    status character varying(32),
    gap_count integer,
    description text,
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: defense_mesh_recommendations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.defense_mesh_recommendations (
    id character varying(64) NOT NULL,
    report_id character varying(64) NOT NULL,
    priority integer,
    pillar character varying(128),
    title character varying(256),
    description text,
    effort character varying(32),
    impact character varying(32),
    timeframe character varying(64),
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: defense_mesh_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.defense_mesh_reports (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    organisation character varying(256),
    defense_score double precision,
    maturity_level character varying(64),
    total_gaps integer,
    critical_gaps integer,
    summary text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: defense_playbooks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.defense_playbooks (
    id integer NOT NULL,
    name character varying(200) NOT NULL,
    description text,
    enabled boolean,
    trigger_field character varying(50) NOT NULL,
    trigger_op character varying(20) NOT NULL,
    trigger_value character varying(200) NOT NULL,
    actions text NOT NULL,
    cooldown_minutes integer,
    trigger_count integer,
    last_triggered timestamp without time zone,
    created_by integer,
    created_at timestamp without time zone
);


--
-- Name: defense_playbooks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.defense_playbooks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: defense_playbooks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.defense_playbooks_id_seq OWNED BY public.defense_playbooks.id;


--
-- Name: device_risk_score_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_risk_score_history (
    id integer NOT NULL,
    user_id integer NOT NULL,
    entity character varying(256) NOT NULL,
    entity_type character varying(32),
    score integer NOT NULL,
    event_count_24h integer,
    contributing_modules json,
    snapshot_at timestamp without time zone NOT NULL,
    node_meta json
);


--
-- Name: device_risk_score_history_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.device_risk_score_history_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: device_risk_score_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.device_risk_score_history_id_seq OWNED BY public.device_risk_score_history.id;


--
-- Name: device_risk_scores; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_risk_scores (
    id integer NOT NULL,
    user_id integer NOT NULL,
    entity character varying(256) NOT NULL,
    entity_type character varying(32),
    score integer NOT NULL,
    event_count_24h integer,
    contributing_modules json,
    top_contributors json,
    last_updated_at timestamp without time zone NOT NULL,
    last_recomputed_at timestamp without time zone NOT NULL,
    node_meta json
);


--
-- Name: device_risk_scores_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.device_risk_scores_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: device_risk_scores_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.device_risk_scores_id_seq OWNED BY public.device_risk_scores.id;


--
-- Name: device_tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_tags (
    id integer NOT NULL,
    user_id integer NOT NULL,
    device_ip character varying(255) NOT NULL,
    business_function character varying(100) NOT NULL,
    industry character varying(100) NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: device_tags_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.device_tags_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: device_tags_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.device_tags_id_seq OWNED BY public.device_tags.id;


--
-- Name: digital_twin_v2_anomalies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.digital_twin_v2_anomalies (
    id character varying(64) NOT NULL,
    env_id character varying(64) NOT NULL,
    device_name character varying(256),
    anomaly_type character varying(64),
    severity character varying(16),
    description text,
    recommendation text,
    mitre_tactic character varying(128),
    detected_at timestamp without time zone,
    node_meta text
);


--
-- Name: digital_twin_v2_devices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.digital_twin_v2_devices (
    id character varying(64) NOT NULL,
    env_id character varying(64) NOT NULL,
    device_name character varying(256),
    device_type character varying(64),
    ip_address character varying(64),
    status character varying(32),
    risk_level character varying(16),
    cpu_usage double precision,
    memory_usage double precision,
    last_seen timestamp without time zone,
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: digital_twin_v2_environments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.digital_twin_v2_environments (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    name character varying(256),
    env_type character varying(64),
    device_count integer,
    risk_score double precision,
    health_score double precision,
    anomaly_count integer,
    status character varying(32),
    summary text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: dspm_datastores; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dspm_datastores (
    id integer NOT NULL,
    name character varying(200) NOT NULL,
    store_type character varying(50) NOT NULL,
    location character varying(200),
    cloud_provider character varying(50),
    sensitivity character varying(50),
    data_types text,
    size_gb double precision,
    record_count integer,
    encrypted_at_rest boolean,
    encrypted_in_transit boolean,
    access_control character varying(50),
    publicly_accessible boolean,
    risk_score integer,
    finding_count integer,
    last_scanned timestamp without time zone,
    created_at timestamp without time zone
);


--
-- Name: dspm_datastores_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dspm_datastores_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dspm_datastores_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dspm_datastores_id_seq OWNED BY public.dspm_datastores.id;


--
-- Name: dspm_findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dspm_findings (
    id integer NOT NULL,
    datastore_id integer NOT NULL,
    finding_type character varying(100) NOT NULL,
    severity character varying(20),
    title character varying(300) NOT NULL,
    description text,
    remediation text,
    regulation character varying(200),
    status character varying(30),
    created_at timestamp without time zone
);


--
-- Name: dspm_findings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dspm_findings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dspm_findings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dspm_findings_id_seq OWNED BY public.dspm_findings.id;


--
-- Name: dspm_scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dspm_scans (
    id integer NOT NULL,
    datastores_found integer,
    findings_found integer,
    critical_count integer,
    duration_sec integer,
    created_at timestamp without time zone
);


--
-- Name: dspm_scans_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dspm_scans_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dspm_scans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dspm_scans_id_seq OWNED BY public.dspm_scans.id;


--
-- Name: endpoint_findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.endpoint_findings (
    id character varying(64) NOT NULL,
    scan_id character varying(64) NOT NULL,
    category character varying(64),
    title character varying(256),
    severity character varying(16),
    tactic character varying(128),
    technique character varying(128),
    description text,
    remediation text,
    ioc character varying(256),
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: endpoint_scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.endpoint_scans (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    hostname character varying(256),
    os_type character varying(64),
    os_version character varying(64),
    risk_score double precision,
    severity character varying(16),
    total_findings integer,
    critical_count integer,
    health_score double precision,
    summary text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: enterprise_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.enterprise_reports (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    report_type character varying(64),
    organisation character varying(256),
    period character varying(64),
    risk_score double precision,
    status character varying(32),
    content text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: explain_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.explain_results (
    id integer NOT NULL,
    scan_id integer,
    finding_id integer,
    explain_type character varying(50) NOT NULL,
    content text NOT NULL,
    model_used character varying(100) NOT NULL,
    tokens_used integer,
    created_at timestamp without time zone
);


--
-- Name: explain_results_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.explain_results_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: explain_results_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.explain_results_id_seq OWNED BY public.explain_results.id;


--
-- Name: findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.findings (
    id integer NOT NULL,
    scan_id integer NOT NULL,
    module character varying(100) NOT NULL,
    attack character varying(255) NOT NULL,
    severity character varying(50) NOT NULL,
    description text,
    target character varying(255),
    created_at timestamp without time zone,
    fix_status character varying(50),
    fix_notes text
);


--
-- Name: findings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.findings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: findings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.findings_id_seq OWNED BY public.findings.id;


--
-- Name: forecast_alerts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.forecast_alerts (
    id integer NOT NULL,
    user_id integer NOT NULL,
    entity character varying(256) NOT NULL,
    entity_type character varying(32),
    threshold_name character varying(64) NOT NULL,
    threshold_value integer NOT NULL,
    current_score integer NOT NULL,
    predicted_crossing_date timestamp without time zone NOT NULL,
    probability double precision NOT NULL,
    model_used character varying(32),
    history_points integer,
    horizon_days integer,
    status character varying(32),
    acknowledged_at timestamp without time zone,
    created_at timestamp without time zone NOT NULL,
    node_meta json
);


--
-- Name: forecast_alerts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.forecast_alerts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: forecast_alerts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.forecast_alerts_id_seq OWNED BY public.forecast_alerts.id;


--
-- Name: forensic_artifacts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.forensic_artifacts (
    id character varying(64) NOT NULL,
    case_id character varying(64) NOT NULL,
    artifact_type character varying(32),
    value character varying(512),
    source character varying(256),
    confidence character varying(16),
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: forensic_cases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.forensic_cases (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    title character varying(256),
    severity character varying(16),
    status character varying(32),
    risk_score double precision,
    summary text,
    created_at timestamp without time zone,
    completed_at timestamp without time zone,
    node_meta text
);


--
-- Name: forensic_timeline; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.forensic_timeline (
    id character varying(64) NOT NULL,
    case_id character varying(64) NOT NULL,
    step integer,
    stage character varying(64),
    description text,
    mitre_tactic character varying(128),
    mitre_technique character varying(128),
    severity character varying(16),
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: iam_exposure_findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.iam_exposure_findings (
    id character varying(64) NOT NULL,
    scan_id character varying(64) NOT NULL,
    category character varying(64),
    title character varying(256),
    severity character varying(16),
    identity_type character varying(64),
    identity_name character varying(256),
    description text,
    remediation text,
    blast_radius character varying(32),
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: iam_exposure_scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.iam_exposure_scans (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    cloud_provider character varying(32),
    risk_score double precision,
    severity character varying(16),
    total_findings integer,
    critical_count integer,
    identities_at_risk integer,
    summary text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: identity_guardian_alerts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_guardian_alerts (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    subject character varying(256),
    risk_score double precision,
    severity character varying(16),
    status character varying(32),
    summary text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: identity_guardian_signals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_guardian_signals (
    id character varying(64) NOT NULL,
    alert_id character varying(64) NOT NULL,
    signal_type character varying(64),
    title character varying(256),
    description text,
    severity character varying(16),
    recommendation text,
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: ig_edges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ig_edges (
    id integer NOT NULL,
    source_id integer NOT NULL,
    target_id integer NOT NULL,
    relationship character varying(100) NOT NULL,
    weight integer,
    is_risky boolean,
    created_at timestamp without time zone
);


--
-- Name: ig_edges_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ig_edges_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ig_edges_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ig_edges_id_seq OWNED BY public.ig_edges.id;


--
-- Name: ig_identities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ig_identities (
    id integer NOT NULL,
    name character varying(200) NOT NULL,
    identity_type character varying(50) NOT NULL,
    email character varying(200),
    source character varying(100),
    risk_score integer,
    blast_radius integer,
    is_privileged boolean,
    is_dormant boolean,
    is_overprivileged boolean,
    last_active timestamp without time zone,
    permissions text,
    tags text,
    created_at timestamp without time zone
);


--
-- Name: ig_identities_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ig_identities_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ig_identities_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ig_identities_id_seq OWNED BY public.ig_identities.id;


--
-- Name: ig_risks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ig_risks (
    id integer NOT NULL,
    identity_id integer NOT NULL,
    risk_type character varying(100) NOT NULL,
    severity character varying(20),
    description text,
    remediation text,
    resolved boolean,
    created_at timestamp without time zone
);


--
-- Name: ig_risks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ig_risks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ig_risks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ig_risks_id_seq OWNED BY public.ig_risks.id;


--
-- Name: ioc_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_entries (
    id integer NOT NULL,
    feed_id integer NOT NULL,
    ioc_type character varying(20) NOT NULL,
    value character varying(500) NOT NULL,
    threat_type character varying(100),
    confidence integer,
    severity character varying(20),
    description text,
    source_ref character varying(500),
    active boolean,
    created_at timestamp without time zone,
    expires_at timestamp without time zone
);


--
-- Name: ioc_entries_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_entries_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_entries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_entries_id_seq OWNED BY public.ioc_entries.id;


--
-- Name: ioc_feeds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_feeds (
    id integer NOT NULL,
    name character varying(200) NOT NULL,
    feed_type character varying(50) NOT NULL,
    description text,
    enabled boolean,
    api_key text,
    last_sync timestamp without time zone,
    entry_count integer,
    created_at timestamp without time zone
);


--
-- Name: ioc_feeds_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_feeds_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_feeds_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_feeds_id_seq OWNED BY public.ioc_feeds.id;


--
-- Name: ir_incidents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ir_incidents (
    id integer NOT NULL,
    title character varying(300) NOT NULL,
    description text,
    status character varying(30),
    priority character varying(10),
    affected text,
    attack_vector character varying(200),
    mitre_id character varying(50),
    assigned_to character varying(200),
    timeline_ref integer,
    resolution text,
    lessons text,
    created_by integer,
    created_at timestamp without time zone,
    resolved_at timestamp without time zone,
    sla_hours integer
);


--
-- Name: ir_incidents_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ir_incidents_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ir_incidents_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ir_incidents_id_seq OWNED BY public.ir_incidents.id;


--
-- Name: ir_tasks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ir_tasks (
    id integer NOT NULL,
    incident_id integer NOT NULL,
    title character varying(300) NOT NULL,
    description text,
    status character varying(20),
    assigned_to character varying(200),
    created_at timestamp without time zone,
    completed_at timestamp without time zone
);


--
-- Name: ir_tasks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ir_tasks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ir_tasks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ir_tasks_id_seq OWNED BY public.ir_tasks.id;


--
-- Name: itdr_findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.itdr_findings (
    id character varying(64) NOT NULL,
    scan_id character varying(64) NOT NULL,
    attack_type character varying(64),
    title character varying(256),
    severity character varying(16),
    affected_identity character varying(256),
    mitre_tactic character varying(128),
    mitre_technique character varying(128),
    description text,
    remediation text,
    urgency character varying(32),
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: itdr_scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.itdr_scans (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    environment character varying(64),
    identity_store character varying(64),
    risk_score double precision,
    severity character varying(16),
    total_findings integer,
    critical_count integer,
    identities_compromised integer,
    summary text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: k8s_findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.k8s_findings (
    id character varying(64) NOT NULL,
    scan_id character varying(64) NOT NULL,
    category character varying(64),
    title character varying(256),
    severity character varying(16),
    resource_type character varying(64),
    namespace character varying(128),
    description text,
    remediation text,
    cis_ref character varying(64),
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: k8s_scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.k8s_scans (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    cluster_name character varying(256),
    k8s_version character varying(32),
    risk_score double precision,
    severity character varying(16),
    total_findings integer,
    critical_count integer,
    summary text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: kev_catalog; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kev_catalog (
    cve_id character varying(32) NOT NULL,
    vendor_project character varying(256),
    product character varying(256),
    vulnerability_name character varying(512),
    date_added date,
    short_description text,
    required_action text,
    due_date date,
    known_ransomware_use character varying(16),
    notes text,
    cwes json,
    node_meta text,
    last_synced_at timestamp without time zone
);


--
-- Name: live_cves; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.live_cves (
    cve_id character varying(32) NOT NULL,
    description text,
    cvss_score double precision,
    severity character varying(16),
    published timestamp without time zone,
    last_modified timestamp without time zone,
    cpe_list text,
    keywords text,
    synced_at timestamp without time zone,
    url character varying(256)
);


--
-- Name: log_analysis_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.log_analysis_reports (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    log_source character varying(128),
    total_lines integer,
    error_count integer,
    warning_count integer,
    anomaly_count integer,
    security_events integer,
    risk_score double precision,
    summary text,
    findings text,
    patterns text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: metrics_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.metrics_reports (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    service_name character varying(256),
    trace_id character varying(64),
    total_spans integer,
    error_spans integer,
    total_duration_ms double precision,
    bottleneck character varying(256),
    anomalies integer,
    summary text,
    spans_data text,
    metrics_data text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: mitre_techniques; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mitre_techniques (
    technique_id character varying(16) NOT NULL,
    name character varying(256),
    tactic character varying(128),
    tactic_id character varying(16),
    description text,
    url character varying(512),
    platforms json,
    is_subtechnique boolean,
    parent_technique_id character varying(16),
    node_meta json,
    last_updated timestamp without time zone
);


--
-- Name: ml_anomaly_detections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ml_anomaly_detections (
    id integer NOT NULL,
    model_version_id integer NOT NULL,
    user_id integer,
    target_ip character varying(100),
    target_device character varying(200),
    is_anomaly boolean NOT NULL,
    anomaly_score double precision NOT NULL,
    severity character varying(20) NOT NULL,
    feature_vector text,
    top_contributors text,
    node_meta text,
    detected_at timestamp without time zone
);


--
-- Name: ml_anomaly_detections_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ml_anomaly_detections_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ml_anomaly_detections_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ml_anomaly_detections_id_seq OWNED BY public.ml_anomaly_detections.id;


--
-- Name: ml_anomaly_model_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ml_anomaly_model_versions (
    id integer NOT NULL,
    version_tag character varying(100) NOT NULL,
    algorithm character varying(50) NOT NULL,
    contamination double precision NOT NULL,
    n_estimators integer NOT NULL,
    feature_names text,
    training_samples integer,
    precision_score double precision,
    recall_score double precision,
    f1_score double precision,
    model_path character varying(500),
    is_active boolean,
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: ml_anomaly_model_versions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ml_anomaly_model_versions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ml_anomaly_model_versions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ml_anomaly_model_versions_id_seq OWNED BY public.ml_anomaly_model_versions.id;


--
-- Name: mp_installs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mp_installs (
    id integer NOT NULL,
    plugin_id integer NOT NULL,
    user_id integer NOT NULL,
    config text,
    enabled boolean,
    installed_at timestamp without time zone
);


--
-- Name: mp_installs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mp_installs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mp_installs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mp_installs_id_seq OWNED BY public.mp_installs.id;


--
-- Name: mp_plugins; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mp_plugins (
    id integer NOT NULL,
    name character varying(200) NOT NULL,
    slug character varying(100) NOT NULL,
    description text,
    long_desc text,
    category character varying(50) NOT NULL,
    publisher character varying(200) NOT NULL,
    version character varying(20),
    icon character varying(10),
    tags text,
    verified boolean,
    free boolean,
    price_gbp double precision,
    install_count integer,
    avg_rating double precision,
    review_count integer,
    active boolean,
    created_at timestamp without time zone
);


--
-- Name: mp_plugins_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mp_plugins_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mp_plugins_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mp_plugins_id_seq OWNED BY public.mp_plugins.id;


--
-- Name: mp_reviews; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mp_reviews (
    id integer NOT NULL,
    plugin_id integer NOT NULL,
    user_id integer NOT NULL,
    rating integer NOT NULL,
    review text,
    created_at timestamp without time zone
);


--
-- Name: mp_reviews_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mp_reviews_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mp_reviews_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mp_reviews_id_seq OWNED BY public.mp_reviews.id;


--
-- Name: multicloud_scale_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.multicloud_scale_reports (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    total_providers integer,
    total_regions integer,
    total_workloads integer,
    security_score double precision,
    cost_risk_score double precision,
    scale_issues integer,
    summary text,
    recommendations text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: network_exposure_assets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.network_exposure_assets (
    id character varying(64) NOT NULL,
    scan_id character varying(64) NOT NULL,
    asset_type character varying(64),
    asset_name character varying(256),
    exposure_level character varying(32),
    public_ip character varying(64),
    open_ports text,
    risk_level character varying(16),
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: network_exposure_paths; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.network_exposure_paths (
    id character varying(64) NOT NULL,
    scan_id character varying(64) NOT NULL,
    path_type character varying(64),
    source character varying(256),
    destination character varying(256),
    severity character varying(16),
    protocol character varying(32),
    port character varying(32),
    description text,
    remediation text,
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: network_exposure_scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.network_exposure_scans (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    environment character varying(64),
    cloud_provider character varying(32),
    risk_score double precision,
    severity character varying(16),
    total_paths integer,
    critical_paths integer,
    exposed_assets integer,
    summary text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: nv_edges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.nv_edges (
    id integer NOT NULL,
    source_id integer NOT NULL,
    target_id integer NOT NULL,
    protocol character varying(50) NOT NULL,
    port integer,
    encrypted boolean,
    risk_level character varying(20),
    cross_zone boolean,
    bidirectional boolean,
    traffic_gbday double precision,
    created_at timestamp without time zone
);


--
-- Name: nv_edges_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.nv_edges_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: nv_edges_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.nv_edges_id_seq OWNED BY public.nv_edges.id;


--
-- Name: nv_issues; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.nv_issues (
    id integer NOT NULL,
    node_id integer,
    edge_id integer,
    severity character varying(20),
    title character varying(300) NOT NULL,
    description text,
    remediation text,
    status character varying(30),
    created_at timestamp without time zone
);


--
-- Name: nv_issues_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.nv_issues_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: nv_issues_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.nv_issues_id_seq OWNED BY public.nv_issues.id;


--
-- Name: nv_nodes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.nv_nodes (
    id integer NOT NULL,
    name character varying(200) NOT NULL,
    node_type character varying(50) NOT NULL,
    zone character varying(50) NOT NULL,
    cloud_provider character varying(50),
    ip_address character varying(50),
    region character varying(100),
    risk_score integer,
    internet_facing boolean,
    encrypted boolean,
    issue_count integer,
    status character varying(30),
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: nv_nodes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.nv_nodes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: nv_nodes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.nv_nodes_id_seq OWNED BY public.nv_nodes.id;


--
-- Name: ot_devices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ot_devices (
    id integer NOT NULL,
    device_ip character varying(100) NOT NULL,
    device_name character varying(200),
    protocol character varying(50) NOT NULL,
    port integer,
    vendor character varying(200),
    model character varying(200),
    firmware character varying(100),
    zone character varying(50),
    criticality character varying(20),
    location character varying(200),
    last_seen timestamp without time zone,
    online boolean,
    created_at timestamp without time zone
);


--
-- Name: ot_devices_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ot_devices_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ot_devices_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ot_devices_id_seq OWNED BY public.ot_devices.id;


--
-- Name: ot_findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ot_findings (
    id integer NOT NULL,
    scan_id integer,
    device_ip character varying(100) NOT NULL,
    protocol character varying(50) NOT NULL,
    finding_type character varying(100) NOT NULL,
    severity character varying(20) NOT NULL,
    title character varying(500) NOT NULL,
    description text,
    evidence text,
    mitre_ics_id character varying(50),
    remediation text,
    created_at timestamp without time zone
);


--
-- Name: ot_findings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ot_findings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ot_findings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ot_findings_id_seq OWNED BY public.ot_findings.id;


--
-- Name: ot_scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ot_scans (
    id integer NOT NULL,
    target character varying(200) NOT NULL,
    protocol character varying(50) NOT NULL,
    status character varying(30),
    findings_count integer,
    risk_level character varying(20),
    scan_duration double precision,
    user_id integer,
    created_at timestamp without time zone,
    completed_at timestamp without time zone
);


--
-- Name: ot_scans_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ot_scans_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ot_scans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ot_scans_id_seq OWNED BY public.ot_scans.id;


--
-- Name: password_reset_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.password_reset_tokens (
    id integer NOT NULL,
    user_id integer NOT NULL,
    token character varying(128) NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    used boolean,
    created_at timestamp without time zone
);


--
-- Name: password_reset_tokens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.password_reset_tokens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: password_reset_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.password_reset_tokens_id_seq OWNED BY public.password_reset_tokens.id;


--
-- Name: patch_brain_items; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_brain_items (
    id character varying(64) NOT NULL,
    session_id character varying(64) NOT NULL,
    cve_id character varying(32),
    component character varying(256),
    current_version character varying(64),
    fixed_version character varying(64),
    severity character varying(16),
    cvss_score double precision,
    priority integer,
    patch_action text,
    deadline character varying(64),
    exploited integer,
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: patch_brain_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_brain_sessions (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    environment character varying(64),
    risk_score double precision,
    severity character varying(16),
    total_patches integer,
    critical_count integer,
    high_count integer,
    summary text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.permissions (
    id character varying(36) NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    resource character varying(50),
    action character varying(50)
);


--
-- Name: policy_brain_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.policy_brain_policies (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    title character varying(256),
    policy_type character varying(64),
    framework_map text,
    coverage_score double precision,
    word_count integer,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: policy_brain_sections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.policy_brain_sections (
    id character varying(64) NOT NULL,
    policy_id character varying(64) NOT NULL,
    section_number integer,
    section_title character varying(256),
    content text,
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: predict_alerts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.predict_alerts (
    id integer NOT NULL,
    user_id integer NOT NULL,
    cve_id character varying(50) NOT NULL,
    title character varying(500) NOT NULL,
    description text NOT NULL,
    severity character varying(50) NOT NULL,
    cvss_score double precision,
    affected_devices json,
    weaponisation_pct integer,
    published_date timestamp without time zone NOT NULL,
    nvd_url character varying(500),
    is_reviewed boolean,
    created_at timestamp without time zone
);


--
-- Name: predict_alerts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.predict_alerts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: predict_alerts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.predict_alerts_id_seq OWNED BY public.predict_alerts.id;


--
-- Name: protocol_scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.protocol_scans (
    id integer NOT NULL,
    user_id integer NOT NULL,
    protocol character varying(50) NOT NULL,
    target character varying(255) NOT NULL,
    status character varying(50),
    findings json,
    device_count integer,
    risk_level character varying(50),
    created_at timestamp without time zone,
    completed_at timestamp without time zone
);


--
-- Name: protocol_scans_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.protocol_scans_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: protocol_scans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.protocol_scans_id_seq OWNED BY public.protocol_scans.id;


--
-- Name: push_subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.push_subscriptions (
    id integer NOT NULL,
    user_id integer NOT NULL,
    endpoint text NOT NULL,
    p256dh_key text NOT NULL,
    auth_secret text NOT NULL,
    user_agent character varying(512),
    device_label character varying(128),
    enabled boolean NOT NULL,
    last_sent_at timestamp with time zone,
    last_failure_at timestamp with time zone,
    failure_count integer NOT NULL,
    created_at timestamp with time zone NOT NULL,
    node_meta json
);


--
-- Name: push_subscriptions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.push_subscriptions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: push_subscriptions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.push_subscriptions_id_seq OWNED BY public.push_subscriptions.id;


--
-- Name: rbac_assessments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rbac_assessments (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    organisation character varying(256),
    total_roles integer,
    over_privileged integer,
    sso_configured integer,
    mfa_enforced integer,
    risk_score double precision,
    issues integer,
    summary text,
    findings text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: rbac_roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rbac_roles (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    role_name character varying(128),
    role_type character varying(64),
    permissions text,
    description text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: re_assets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.re_assets (
    id integer NOT NULL,
    name character varying(200) NOT NULL,
    asset_type character varying(50) NOT NULL,
    criticality character varying(20),
    location character varying(200),
    rto_target double precision,
    rpo_target double precision,
    rto_actual double precision,
    rpo_actual double precision,
    has_dr_plan boolean,
    has_backup boolean,
    backup_tested boolean,
    failover_ready boolean,
    readiness_score integer,
    last_tested timestamp without time zone,
    created_at timestamp without time zone
);


--
-- Name: re_assets_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.re_assets_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: re_assets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.re_assets_id_seq OWNED BY public.re_assets.id;


--
-- Name: re_plans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.re_plans (
    id integer NOT NULL,
    asset_id integer NOT NULL,
    title character varying(300) NOT NULL,
    description text,
    steps text,
    contacts text,
    status character varying(30),
    last_reviewed timestamp without time zone,
    created_at timestamp without time zone
);


--
-- Name: re_plans_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.re_plans_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: re_plans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.re_plans_id_seq OWNED BY public.re_plans.id;


--
-- Name: re_tests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.re_tests (
    id integer NOT NULL,
    asset_id integer NOT NULL,
    test_type character varying(50) NOT NULL,
    result character varying(20),
    rto_achieved double precision,
    rpo_achieved double precision,
    notes text,
    conducted_by character varying(200),
    created_at timestamp without time zone
);


--
-- Name: re_tests_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.re_tests_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: re_tests_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.re_tests_id_seq OWNED BY public.re_tests.id;


--
-- Name: real_scan_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.real_scan_results (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    target character varying(256) NOT NULL,
    status character varying(32),
    started_at timestamp without time zone,
    finished_at timestamp without time zone,
    hosts_found integer,
    cve_count integer,
    results_json text,
    error text
);


--
-- Name: realtime_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.realtime_snapshots (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    security_score double precision,
    threat_level character varying(16),
    active_threats integer,
    open_incidents integer,
    compliance_pct double precision,
    uptime_pct double precision,
    events_per_min double precision,
    widgets_data text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: remediation_kb; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.remediation_kb (
    id integer NOT NULL,
    attack_type character varying(255) NOT NULL,
    title character varying(255) NOT NULL,
    severity character varying(50) NOT NULL,
    explanation text NOT NULL,
    fix_commands text NOT NULL,
    time_estimate_minutes integer NOT NULL,
    difficulty character varying(50) NOT NULL,
    source character varying(255),
    created_at timestamp without time zone
);


--
-- Name: remediation_kb_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.remediation_kb_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: remediation_kb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.remediation_kb_id_seq OWNED BY public.remediation_kb.id;


--
-- Name: response_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.response_history (
    id integer NOT NULL,
    user_id integer NOT NULL,
    entity character varying(256) NOT NULL,
    entity_type character varying(32),
    playbook_id integer NOT NULL,
    threshold_id integer,
    triggering_score integer NOT NULL,
    threshold_min_score integer NOT NULL,
    threshold_name character varying(64),
    actions_executed json,
    status character varying(32),
    slack_sent boolean,
    teams_sent boolean,
    notification_error text,
    fired_at timestamp without time zone NOT NULL,
    central_event_id integer,
    node_meta json
);


--
-- Name: response_history_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.response_history_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: response_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.response_history_id_seq OWNED BY public.response_history.id;


--
-- Name: response_thresholds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.response_thresholds (
    id integer NOT NULL,
    user_id integer NOT NULL,
    name character varying(64) NOT NULL,
    description character varying(256),
    min_score integer NOT NULL,
    playbook_id integer,
    enabled boolean NOT NULL,
    cooldown_hours integer NOT NULL,
    node_meta json,
    created_at timestamp without time zone,
    last_modified_at timestamp without time zone
);


--
-- Name: response_thresholds_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.response_thresholds_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: response_thresholds_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.response_thresholds_id_seq OWNED BY public.response_thresholds.id;


--
-- Name: risk_narratives; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.risk_narratives (
    id integer NOT NULL,
    audience character varying(50),
    narrative text NOT NULL,
    risk_score integer,
    findings integer,
    devices integer,
    tokens_used integer,
    created_by integer,
    created_at timestamp without time zone
);


--
-- Name: risk_narratives_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.risk_narratives_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: risk_narratives_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.risk_narratives_id_seq OWNED BY public.risk_narratives.id;


--
-- Name: role_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.role_permissions (
    role_id character varying(36) NOT NULL,
    permission_id character varying(36) NOT NULL
);


--
-- Name: roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.roles (
    id character varying(36) NOT NULL,
    name character varying(50) NOT NULL,
    description text,
    created_at timestamp without time zone
);


--
-- Name: rt_attacks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rt_attacks (
    id integer NOT NULL,
    campaign_id integer NOT NULL,
    mitre_id character varying(50) NOT NULL,
    tactic character varying(100) NOT NULL,
    technique character varying(200) NOT NULL,
    target character varying(200),
    result character varying(30),
    impact text,
    evidence text,
    blocked_by character varying(200),
    severity character varying(20),
    executed_at timestamp without time zone,
    created_at timestamp without time zone
);


--
-- Name: rt_attacks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.rt_attacks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: rt_attacks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.rt_attacks_id_seq OWNED BY public.rt_attacks.id;


--
-- Name: rt_campaigns; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rt_campaigns (
    id integer NOT NULL,
    name character varying(200) NOT NULL,
    description text,
    scope text,
    objectives text,
    status character varying(30),
    attack_count integer,
    success_count integer,
    blocked_count integer,
    overall_score integer,
    duration_sec integer,
    created_by integer,
    created_at timestamp without time zone,
    completed_at timestamp without time zone
);


--
-- Name: rt_campaigns_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.rt_campaigns_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: rt_campaigns_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.rt_campaigns_id_seq OWNED BY public.rt_campaigns.id;


--
-- Name: runtime_protection_findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.runtime_protection_findings (
    id character varying(64) NOT NULL,
    scan_id character varying(64) NOT NULL,
    category character varying(64),
    title character varying(256),
    severity character varying(16),
    technique character varying(128),
    description text,
    remediation text,
    confidence character varying(16),
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: runtime_protection_scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.runtime_protection_scans (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    workload_type character varying(64),
    workload_name character varying(256),
    risk_score double precision,
    severity character varying(16),
    total_findings integer,
    critical_count integer,
    summary text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: sandbox_analyses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sandbox_analyses (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    sample_name character varying(256),
    file_type character varying(64),
    sha256 character varying(64),
    verdict character varying(32),
    malware_family character varying(128),
    threat_score double precision,
    severity character varying(16),
    behaviours integer,
    iocs_found integer,
    summary text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: sandbox_findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sandbox_findings (
    id character varying(64) NOT NULL,
    analysis_id character varying(64) NOT NULL,
    category character varying(64),
    finding_type character varying(64),
    title character varying(256),
    severity character varying(16),
    description text,
    ioc character varying(512),
    mitre_technique character varying(128),
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: sc_components; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sc_components (
    id integer NOT NULL,
    name character varying(200) NOT NULL,
    version character varying(50),
    component_type character varying(50) NOT NULL,
    ecosystem character varying(50),
    license character varying(100),
    supplier character varying(200),
    used_in text,
    direct_dep boolean,
    vuln_count integer,
    critical_vulns integer,
    risk_level character varying(20),
    license_risk character varying(20),
    last_updated timestamp without time zone,
    created_at timestamp without time zone
);


--
-- Name: sc_components_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sc_components_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sc_components_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sc_components_id_seq OWNED BY public.sc_components.id;


--
-- Name: sc_sboms; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sc_sboms (
    id integer NOT NULL,
    name character varying(200) NOT NULL,
    format character varying(50),
    version character varying(20),
    components_count integer,
    vuln_count integer,
    content text,
    created_at timestamp without time zone
);


--
-- Name: sc_sboms_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sc_sboms_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sc_sboms_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sc_sboms_id_seq OWNED BY public.sc_sboms.id;


--
-- Name: sc_vulns; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sc_vulns (
    id integer NOT NULL,
    component_id integer NOT NULL,
    cve_id character varying(50) NOT NULL,
    severity character varying(20),
    cvss_score double precision,
    title character varying(300) NOT NULL,
    description text,
    fixed_version character varying(50),
    exploit_public boolean,
    cisa_kev boolean,
    status character varying(30),
    created_at timestamp without time zone
);


--
-- Name: sc_vulns_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sc_vulns_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sc_vulns_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sc_vulns_id_seq OWNED BY public.sc_vulns.id;


--
-- Name: scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scans (
    id integer NOT NULL,
    user_id integer NOT NULL,
    target character varying(255) NOT NULL,
    mode character varying(50),
    status character varying(50),
    result_dir character varying(500),
    report_path character varying(500),
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    created_at timestamp without time zone,
    critical integer,
    high integer,
    medium integer,
    low integer
);


--
-- Name: scans_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.scans_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: scans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.scans_id_seq OWNED BY public.scans.id;


--
-- Name: score_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.score_results (
    id integer NOT NULL,
    scan_id integer NOT NULL,
    user_id integer NOT NULL,
    industry character varying(100) NOT NULL,
    total_exposure_gbp bigint NOT NULL,
    findings_breakdown json,
    created_at timestamp without time zone
);


--
-- Name: score_results_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.score_results_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: score_results_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.score_results_id_seq OWNED BY public.score_results.id;


--
-- Name: siem_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.siem_events (
    id integer NOT NULL,
    event_type character varying(100) NOT NULL,
    source character varying(200) NOT NULL,
    severity character varying(20) NOT NULL,
    title character varying(500) NOT NULL,
    description text,
    raw_payload text,
    mitre_id character varying(50),
    user_id integer,
    incident_id integer,
    acknowledged boolean,
    created_at timestamp without time zone
);


--
-- Name: siem_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.siem_events_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: siem_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.siem_events_id_seq OWNED BY public.siem_events.id;


--
-- Name: siem_incidents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.siem_incidents (
    id integer NOT NULL,
    title character varying(500) NOT NULL,
    description text,
    severity character varying(20) NOT NULL,
    status character varying(50),
    assigned_to integer,
    created_by integer,
    event_count integer,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: siem_incidents_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.siem_incidents_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: siem_incidents_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.siem_incidents_id_seq OWNED BY public.siem_incidents.id;


--
-- Name: siem_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.siem_reports (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    event_source character varying(128),
    total_events integer,
    correlated integer,
    critical_alerts integer,
    incidents integer,
    risk_score double precision,
    summary text,
    alerts text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: siem_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.siem_rules (
    id integer NOT NULL,
    name character varying(200) NOT NULL,
    description text,
    condition text NOT NULL,
    action character varying(50),
    severity character varying(20),
    enabled boolean,
    trigger_count integer,
    created_by integer,
    created_at timestamp without time zone
);


--
-- Name: siem_rules_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.siem_rules_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: siem_rules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.siem_rules_id_seq OWNED BY public.siem_rules.id;


--
-- Name: soc_twin_actions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.soc_twin_actions (
    id character varying(64) NOT NULL,
    session_id character varying(64) NOT NULL,
    priority integer,
    phase character varying(64),
    action text,
    owner character varying(128),
    timeframe character varying(64),
    mitre_ref character varying(128),
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: soc_twin_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.soc_twin_sessions (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    scenario_name character varying(256),
    scenario_type character varying(64),
    threat_actor character varying(128),
    severity character varying(16),
    risk_score double precision,
    impact_score double precision,
    status character varying(32),
    summary text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: sso_providers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sso_providers (
    id character varying(36) NOT NULL,
    name character varying(50) NOT NULL,
    client_id text,
    tenant_id text,
    metadata_url text,
    enabled boolean,
    created_at timestamp without time zone
);


--
-- Name: synthetic_checks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.synthetic_checks (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    check_name character varying(256),
    check_type character varying(64),
    target_url character varying(512),
    overall_status character varying(16),
    uptime_pct double precision,
    avg_latency_ms double precision,
    sla_met integer,
    total_checks integer,
    failed_checks integer,
    issues integer,
    summary text,
    results_data text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: te_clusters; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.te_clusters (
    id integer NOT NULL,
    title character varying(300) NOT NULL,
    cluster_type character varying(50) NOT NULL,
    severity character varying(20),
    event_count integer,
    modules_involved text,
    ai_summary text,
    status character varying(30),
    started_at timestamp without time zone,
    created_at timestamp without time zone
);


--
-- Name: te_clusters_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.te_clusters_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: te_clusters_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.te_clusters_id_seq OWNED BY public.te_clusters.id;


--
-- Name: te_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.te_events (
    id integer NOT NULL,
    source_module character varying(50) NOT NULL,
    event_type character varying(100) NOT NULL,
    severity character varying(20),
    title character varying(300) NOT NULL,
    description text,
    entity character varying(200),
    entity_type character varying(50),
    mitre_id character varying(50),
    cluster_id integer,
    correlated boolean,
    risk_score integer,
    raw_ref_id integer,
    resolved boolean,
    created_at timestamp without time zone
);


--
-- Name: te_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.te_events_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: te_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.te_events_id_seq OWNED BY public.te_events.id;


--
-- Name: tenant_assessments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_assessments (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    tenant_name character varying(256),
    tenant_type character varying(64),
    isolation_score double precision,
    risk_score double precision,
    total_tenants integer,
    issues integer,
    summary text,
    findings text,
    tenants_data text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: terminal_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.terminal_audit_log (
    id integer NOT NULL,
    user_id integer NOT NULL,
    session_key character varying(100),
    raw_input character varying(500) NOT NULL,
    parsed_cmd character varying(200),
    module character varying(100),
    success boolean,
    error text,
    duration_ms integer,
    ip_address character varying(50),
    created_at timestamp without time zone
);


--
-- Name: terminal_audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.terminal_audit_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: terminal_audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.terminal_audit_log_id_seq OWNED BY public.terminal_audit_log.id;


--
-- Name: terminal_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.terminal_sessions (
    id integer NOT NULL,
    user_id integer NOT NULL,
    session_key character varying(100) NOT NULL,
    last_command character varying(500),
    context text,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: terminal_sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.terminal_sessions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: terminal_sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.terminal_sessions_id_seq OWNED BY public.terminal_sessions.id;


--
-- Name: threat_intel_feeds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_intel_feeds (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    feed_name character varying(256),
    feed_type character varying(64),
    total_iocs integer,
    critical_iocs integer,
    threat_actors integer,
    ttps_mapped integer,
    risk_score double precision,
    summary text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: threat_intel_iocs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_intel_iocs (
    id character varying(64) NOT NULL,
    feed_id character varying(64) NOT NULL,
    ioc_type character varying(32),
    ioc_value character varying(512),
    severity character varying(16),
    confidence character varying(16),
    threat_actor character varying(128),
    ttp character varying(128),
    description text,
    first_seen character varying(32),
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: threat_matches; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_matches (
    id integer NOT NULL,
    ioc_entry_id integer,
    scan_id integer,
    matched_value character varying(500) NOT NULL,
    match_source character varying(100) NOT NULL,
    threat_type character varying(100),
    confidence integer,
    severity character varying(20),
    details text,
    user_id integer,
    created_at timestamp without time zone
);


--
-- Name: threat_matches_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.threat_matches_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: threat_matches_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.threat_matches_id_seq OWNED BY public.threat_matches.id;


--
-- Name: threat_radar_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_radar_reports (
    id character varying(64) NOT NULL,
    user_id integer NOT NULL,
    organisation character varying(256),
    region character varying(64),
    sector character varying(64),
    risk_score double precision,
    severity character varying(16),
    threat_count integer,
    summary text,
    created_at timestamp without time zone,
    node_meta text
);


--
-- Name: threat_radar_threats; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_radar_threats (
    id character varying(64) NOT NULL,
    report_id character varying(64) NOT NULL,
    threat_type character varying(64),
    actor character varying(128),
    severity character varying(16),
    confidence character varying(16),
    description text,
    mitigation text,
    mitre_tactic character varying(128),
    node_meta text,
    created_at timestamp without time zone
);


--
-- Name: timeline_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.timeline_events (
    id integer NOT NULL,
    source character varying(50) NOT NULL,
    event_type character varying(100) NOT NULL,
    severity character varying(20),
    title character varying(300) NOT NULL,
    detail text,
    entity character varying(200),
    mitre_id character varying(50),
    user_id integer,
    resolved boolean,
    created_at timestamp without time zone
);


--
-- Name: timeline_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.timeline_events_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: timeline_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.timeline_events_id_seq OWNED BY public.timeline_events.id;


--
-- Name: twin_edges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.twin_edges (
    id integer NOT NULL,
    source_id integer NOT NULL,
    target_id integer NOT NULL,
    edge_type character varying(50),
    protocol character varying(50),
    port integer,
    encrypted boolean,
    bandwidth character varying(50),
    latency_ms integer,
    active boolean,
    created_at timestamp without time zone
);


--
-- Name: twin_edges_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.twin_edges_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: twin_edges_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.twin_edges_id_seq OWNED BY public.twin_edges.id;


--
-- Name: twin_nodes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.twin_nodes (
    id integer NOT NULL,
    name character varying(200) NOT NULL,
    node_type character varying(50) NOT NULL,
    ip_address character varying(100),
    mac_address character varying(50),
    vendor character varying(200),
    firmware character varying(100),
    location character varying(200),
    zone character varying(50),
    expected_state text,
    actual_state text,
    diverged boolean,
    risk_score integer,
    online boolean,
    x_pos double precision,
    y_pos double precision,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: twin_nodes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.twin_nodes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: twin_nodes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.twin_nodes_id_seq OWNED BY public.twin_nodes.id;


--
-- Name: twin_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.twin_snapshots (
    id integer NOT NULL,
    label character varying(200),
    snapshot_type character varying(50),
    node_count integer,
    edge_count integer,
    diverged_count integer,
    risk_avg double precision,
    data text,
    created_by integer,
    created_at timestamp without time zone
);


--
-- Name: twin_snapshots_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.twin_snapshots_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: twin_snapshots_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.twin_snapshots_id_seq OWNED BY public.twin_snapshots.id;


--
-- Name: user_roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_roles (
    id character varying(36) NOT NULL,
    user_id integer NOT NULL,
    role_id character varying(36) NOT NULL,
    assigned_by integer,
    assigned_at timestamp without time zone
);


--
-- Name: user_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_settings (
    id integer NOT NULL,
    user_id integer NOT NULL,
    slack_webhook_url text,
    teams_webhook_url text,
    notify_critical boolean,
    notify_high boolean,
    notify_cve boolean,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: user_settings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.user_settings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: user_settings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.user_settings_id_seq OWNED BY public.user_settings.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id integer NOT NULL,
    email character varying(255) NOT NULL,
    password_hash character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    plan character varying(50),
    scans_used integer,
    scans_limit integer,
    created_at timestamp without time zone,
    last_login timestamp without time zone,
    is_active boolean,
    stripe_customer_id character varying(100),
    stripe_subscription_id character varying(100),
    plan_expires_at timestamp without time zone,
    onboarding_complete boolean,
    organisation character varying(255),
    industry character varying(100)
);


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: watch_alerts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.watch_alerts (
    id integer NOT NULL,
    user_id integer NOT NULL,
    device_ip character varying(255) NOT NULL,
    alert_type character varying(100) NOT NULL,
    severity character varying(50) NOT NULL,
    description text NOT NULL,
    details json,
    is_acknowledged boolean,
    created_at timestamp without time zone
);


--
-- Name: watch_alerts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.watch_alerts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: watch_alerts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.watch_alerts_id_seq OWNED BY public.watch_alerts.id;


--
-- Name: watch_baselines; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.watch_baselines (
    id integer NOT NULL,
    user_id integer NOT NULL,
    device_ip character varying(255) NOT NULL,
    device_function character varying(100),
    baseline_data json NOT NULL,
    first_seen timestamp without time zone,
    last_seen timestamp without time zone,
    is_active boolean,
    created_at timestamp without time zone
);


--
-- Name: watch_baselines_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.watch_baselines_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: watch_baselines_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.watch_baselines_id_seq OWNED BY public.watch_baselines.id;


--
-- Name: zt_access_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.zt_access_log (
    id integer NOT NULL,
    source_ip character varying(100) NOT NULL,
    dest_ip character varying(100),
    port character varying(50),
    protocol character varying(20),
    action character varying(30) NOT NULL,
    policy_id integer,
    policy_name character varying(200),
    reason text,
    trust_score integer,
    created_at timestamp without time zone
);


--
-- Name: zt_access_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.zt_access_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: zt_access_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.zt_access_log_id_seq OWNED BY public.zt_access_log.id;


--
-- Name: zt_device_trust; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.zt_device_trust (
    id integer NOT NULL,
    device_ip character varying(100) NOT NULL,
    device_name character varying(200),
    trust_score integer,
    status character varying(30),
    risk_factors text,
    last_scan_id integer,
    last_assessed timestamp without time zone,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: zt_device_trust_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.zt_device_trust_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: zt_device_trust_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.zt_device_trust_id_seq OWNED BY public.zt_device_trust.id;


--
-- Name: zt_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.zt_policies (
    id integer NOT NULL,
    name character varying(200) NOT NULL,
    description text,
    source character varying(200) NOT NULL,
    destination character varying(200) NOT NULL,
    port character varying(50),
    protocol character varying(20),
    action character varying(30) NOT NULL,
    priority integer,
    enabled boolean,
    hit_count integer,
    created_by integer,
    created_at timestamp without time zone
);


--
-- Name: zt_policies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.zt_policies_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: zt_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.zt_policies_id_seq OWNED BY public.zt_policies.id;


--
-- Name: agent_api_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_api_keys ALTER COLUMN id SET DEFAULT nextval('public.agent_api_keys_id_seq'::regclass);


--
-- Name: agent_scan_submissions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_scan_submissions ALTER COLUMN id SET DEFAULT nextval('public.agent_scan_submissions_id_seq'::regclass);


--
-- Name: ap_analyses id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ap_analyses ALTER COLUMN id SET DEFAULT nextval('public.ap_analyses_id_seq'::regclass);


--
-- Name: ap_paths id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ap_paths ALTER COLUMN id SET DEFAULT nextval('public.ap_paths_id_seq'::regclass);


--
-- Name: api_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys ALTER COLUMN id SET DEFAULT nextval('public.api_keys_id_seq'::regclass);


--
-- Name: as_endpoints id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.as_endpoints ALTER COLUMN id SET DEFAULT nextval('public.as_endpoints_id_seq'::regclass);


--
-- Name: as_findings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.as_findings ALTER COLUMN id SET DEFAULT nextval('public.as_findings_id_seq'::regclass);


--
-- Name: as_scans id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.as_scans ALTER COLUMN id SET DEFAULT nextval('public.as_scans_id_seq'::regclass);


--
-- Name: ask_usage_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ask_usage_log ALTER COLUMN id SET DEFAULT nextval('public.ask_usage_log_id_seq'::regclass);


--
-- Name: ba_anomalies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ba_anomalies ALTER COLUMN id SET DEFAULT nextval('public.ba_anomalies_id_seq'::regclass);


--
-- Name: ba_baselines id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ba_baselines ALTER COLUMN id SET DEFAULT nextval('public.ba_baselines_id_seq'::regclass);


--
-- Name: ba_patterns id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ba_patterns ALTER COLUMN id SET DEFAULT nextval('public.ba_patterns_id_seq'::regclass);


--
-- Name: ca_assessments id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ca_assessments ALTER COLUMN id SET DEFAULT nextval('public.ca_assessments_id_seq'::regclass);


--
-- Name: ca_controls id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ca_controls ALTER COLUMN id SET DEFAULT nextval('public.ca_controls_id_seq'::regclass);


--
-- Name: ca_frameworks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ca_frameworks ALTER COLUMN id SET DEFAULT nextval('public.ca_frameworks_id_seq'::regclass);


--
-- Name: central_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.central_events ALTER COLUMN id SET DEFAULT nextval('public.central_events_id_seq'::regclass);


--
-- Name: cloud_accounts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cloud_accounts ALTER COLUMN id SET DEFAULT nextval('public.cloud_accounts_id_seq'::regclass);


--
-- Name: cloud_assets id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cloud_assets ALTER COLUMN id SET DEFAULT nextval('public.cloud_assets_id_seq'::regclass);


--
-- Name: cloud_findings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cloud_findings ALTER COLUMN id SET DEFAULT nextval('public.cloud_findings_id_seq'::regclass);


--
-- Name: compliance_results id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_results ALTER COLUMN id SET DEFAULT nextval('public.compliance_results_id_seq'::regclass);


--
-- Name: cs_recommendations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cs_recommendations ALTER COLUMN id SET DEFAULT nextval('public.cs_recommendations_id_seq'::regclass);


--
-- Name: cs_resources id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cs_resources ALTER COLUMN id SET DEFAULT nextval('public.cs_resources_id_seq'::regclass);


--
-- Name: cve_sync_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cve_sync_logs ALTER COLUMN id SET DEFAULT nextval('public.cve_sync_logs_id_seq'::regclass);


--
-- Name: dd_baselines id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dd_baselines ALTER COLUMN id SET DEFAULT nextval('public.dd_baselines_id_seq'::regclass);


--
-- Name: dd_drifts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dd_drifts ALTER COLUMN id SET DEFAULT nextval('public.dd_drifts_id_seq'::regclass);


--
-- Name: dd_scans id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dd_scans ALTER COLUMN id SET DEFAULT nextval('public.dd_scans_id_seq'::regclass);


--
-- Name: defense_actions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.defense_actions ALTER COLUMN id SET DEFAULT nextval('public.defense_actions_id_seq'::regclass);


--
-- Name: defense_playbooks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.defense_playbooks ALTER COLUMN id SET DEFAULT nextval('public.defense_playbooks_id_seq'::regclass);


--
-- Name: device_risk_score_history id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_risk_score_history ALTER COLUMN id SET DEFAULT nextval('public.device_risk_score_history_id_seq'::regclass);


--
-- Name: device_risk_scores id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_risk_scores ALTER COLUMN id SET DEFAULT nextval('public.device_risk_scores_id_seq'::regclass);


--
-- Name: device_tags id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_tags ALTER COLUMN id SET DEFAULT nextval('public.device_tags_id_seq'::regclass);


--
-- Name: dspm_datastores id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dspm_datastores ALTER COLUMN id SET DEFAULT nextval('public.dspm_datastores_id_seq'::regclass);


--
-- Name: dspm_findings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dspm_findings ALTER COLUMN id SET DEFAULT nextval('public.dspm_findings_id_seq'::regclass);


--
-- Name: dspm_scans id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dspm_scans ALTER COLUMN id SET DEFAULT nextval('public.dspm_scans_id_seq'::regclass);


--
-- Name: explain_results id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.explain_results ALTER COLUMN id SET DEFAULT nextval('public.explain_results_id_seq'::regclass);


--
-- Name: findings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings ALTER COLUMN id SET DEFAULT nextval('public.findings_id_seq'::regclass);


--
-- Name: forecast_alerts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.forecast_alerts ALTER COLUMN id SET DEFAULT nextval('public.forecast_alerts_id_seq'::regclass);


--
-- Name: ig_edges id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ig_edges ALTER COLUMN id SET DEFAULT nextval('public.ig_edges_id_seq'::regclass);


--
-- Name: ig_identities id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ig_identities ALTER COLUMN id SET DEFAULT nextval('public.ig_identities_id_seq'::regclass);


--
-- Name: ig_risks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ig_risks ALTER COLUMN id SET DEFAULT nextval('public.ig_risks_id_seq'::regclass);


--
-- Name: ioc_entries id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_entries ALTER COLUMN id SET DEFAULT nextval('public.ioc_entries_id_seq'::regclass);


--
-- Name: ioc_feeds id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_feeds ALTER COLUMN id SET DEFAULT nextval('public.ioc_feeds_id_seq'::regclass);


--
-- Name: ir_incidents id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ir_incidents ALTER COLUMN id SET DEFAULT nextval('public.ir_incidents_id_seq'::regclass);


--
-- Name: ir_tasks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ir_tasks ALTER COLUMN id SET DEFAULT nextval('public.ir_tasks_id_seq'::regclass);


--
-- Name: ml_anomaly_detections id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ml_anomaly_detections ALTER COLUMN id SET DEFAULT nextval('public.ml_anomaly_detections_id_seq'::regclass);


--
-- Name: ml_anomaly_model_versions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ml_anomaly_model_versions ALTER COLUMN id SET DEFAULT nextval('public.ml_anomaly_model_versions_id_seq'::regclass);


--
-- Name: mp_installs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mp_installs ALTER COLUMN id SET DEFAULT nextval('public.mp_installs_id_seq'::regclass);


--
-- Name: mp_plugins id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mp_plugins ALTER COLUMN id SET DEFAULT nextval('public.mp_plugins_id_seq'::regclass);


--
-- Name: mp_reviews id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mp_reviews ALTER COLUMN id SET DEFAULT nextval('public.mp_reviews_id_seq'::regclass);


--
-- Name: nv_edges id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nv_edges ALTER COLUMN id SET DEFAULT nextval('public.nv_edges_id_seq'::regclass);


--
-- Name: nv_issues id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nv_issues ALTER COLUMN id SET DEFAULT nextval('public.nv_issues_id_seq'::regclass);


--
-- Name: nv_nodes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nv_nodes ALTER COLUMN id SET DEFAULT nextval('public.nv_nodes_id_seq'::regclass);


--
-- Name: ot_devices id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ot_devices ALTER COLUMN id SET DEFAULT nextval('public.ot_devices_id_seq'::regclass);


--
-- Name: ot_findings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ot_findings ALTER COLUMN id SET DEFAULT nextval('public.ot_findings_id_seq'::regclass);


--
-- Name: ot_scans id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ot_scans ALTER COLUMN id SET DEFAULT nextval('public.ot_scans_id_seq'::regclass);


--
-- Name: password_reset_tokens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset_tokens ALTER COLUMN id SET DEFAULT nextval('public.password_reset_tokens_id_seq'::regclass);


--
-- Name: predict_alerts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.predict_alerts ALTER COLUMN id SET DEFAULT nextval('public.predict_alerts_id_seq'::regclass);


--
-- Name: protocol_scans id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protocol_scans ALTER COLUMN id SET DEFAULT nextval('public.protocol_scans_id_seq'::regclass);


--
-- Name: push_subscriptions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_subscriptions ALTER COLUMN id SET DEFAULT nextval('public.push_subscriptions_id_seq'::regclass);


--
-- Name: re_assets id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.re_assets ALTER COLUMN id SET DEFAULT nextval('public.re_assets_id_seq'::regclass);


--
-- Name: re_plans id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.re_plans ALTER COLUMN id SET DEFAULT nextval('public.re_plans_id_seq'::regclass);


--
-- Name: re_tests id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.re_tests ALTER COLUMN id SET DEFAULT nextval('public.re_tests_id_seq'::regclass);


--
-- Name: remediation_kb id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_kb ALTER COLUMN id SET DEFAULT nextval('public.remediation_kb_id_seq'::regclass);


--
-- Name: response_history id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.response_history ALTER COLUMN id SET DEFAULT nextval('public.response_history_id_seq'::regclass);


--
-- Name: response_thresholds id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.response_thresholds ALTER COLUMN id SET DEFAULT nextval('public.response_thresholds_id_seq'::regclass);


--
-- Name: risk_narratives id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.risk_narratives ALTER COLUMN id SET DEFAULT nextval('public.risk_narratives_id_seq'::regclass);


--
-- Name: rt_attacks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rt_attacks ALTER COLUMN id SET DEFAULT nextval('public.rt_attacks_id_seq'::regclass);


--
-- Name: rt_campaigns id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rt_campaigns ALTER COLUMN id SET DEFAULT nextval('public.rt_campaigns_id_seq'::regclass);


--
-- Name: sc_components id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sc_components ALTER COLUMN id SET DEFAULT nextval('public.sc_components_id_seq'::regclass);


--
-- Name: sc_sboms id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sc_sboms ALTER COLUMN id SET DEFAULT nextval('public.sc_sboms_id_seq'::regclass);


--
-- Name: sc_vulns id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sc_vulns ALTER COLUMN id SET DEFAULT nextval('public.sc_vulns_id_seq'::regclass);


--
-- Name: scans id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans ALTER COLUMN id SET DEFAULT nextval('public.scans_id_seq'::regclass);


--
-- Name: score_results id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.score_results ALTER COLUMN id SET DEFAULT nextval('public.score_results_id_seq'::regclass);


--
-- Name: siem_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.siem_events ALTER COLUMN id SET DEFAULT nextval('public.siem_events_id_seq'::regclass);


--
-- Name: siem_incidents id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.siem_incidents ALTER COLUMN id SET DEFAULT nextval('public.siem_incidents_id_seq'::regclass);


--
-- Name: siem_rules id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.siem_rules ALTER COLUMN id SET DEFAULT nextval('public.siem_rules_id_seq'::regclass);


--
-- Name: te_clusters id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.te_clusters ALTER COLUMN id SET DEFAULT nextval('public.te_clusters_id_seq'::regclass);


--
-- Name: te_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.te_events ALTER COLUMN id SET DEFAULT nextval('public.te_events_id_seq'::regclass);


--
-- Name: terminal_audit_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.terminal_audit_log ALTER COLUMN id SET DEFAULT nextval('public.terminal_audit_log_id_seq'::regclass);


--
-- Name: terminal_sessions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.terminal_sessions ALTER COLUMN id SET DEFAULT nextval('public.terminal_sessions_id_seq'::regclass);


--
-- Name: threat_matches id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_matches ALTER COLUMN id SET DEFAULT nextval('public.threat_matches_id_seq'::regclass);


--
-- Name: timeline_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.timeline_events ALTER COLUMN id SET DEFAULT nextval('public.timeline_events_id_seq'::regclass);


--
-- Name: twin_edges id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.twin_edges ALTER COLUMN id SET DEFAULT nextval('public.twin_edges_id_seq'::regclass);


--
-- Name: twin_nodes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.twin_nodes ALTER COLUMN id SET DEFAULT nextval('public.twin_nodes_id_seq'::regclass);


--
-- Name: twin_snapshots id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.twin_snapshots ALTER COLUMN id SET DEFAULT nextval('public.twin_snapshots_id_seq'::regclass);


--
-- Name: user_settings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_settings ALTER COLUMN id SET DEFAULT nextval('public.user_settings_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: watch_alerts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.watch_alerts ALTER COLUMN id SET DEFAULT nextval('public.watch_alerts_id_seq'::regclass);


--
-- Name: watch_baselines id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.watch_baselines ALTER COLUMN id SET DEFAULT nextval('public.watch_baselines_id_seq'::regclass);


--
-- Name: zt_access_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.zt_access_log ALTER COLUMN id SET DEFAULT nextval('public.zt_access_log_id_seq'::regclass);


--
-- Name: zt_device_trust id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.zt_device_trust ALTER COLUMN id SET DEFAULT nextval('public.zt_device_trust_id_seq'::regclass);


--
-- Name: zt_policies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.zt_policies ALTER COLUMN id SET DEFAULT nextval('public.zt_policies_id_seq'::regclass);


--
-- Name: adversary_profiles adversary_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.adversary_profiles
    ADD CONSTRAINT adversary_profiles_pkey PRIMARY KEY (id);


--
-- Name: agent_api_keys agent_api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_api_keys
    ADD CONSTRAINT agent_api_keys_pkey PRIMARY KEY (id);


--
-- Name: agent_devices agent_devices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_devices
    ADD CONSTRAINT agent_devices_pkey PRIMARY KEY (id);


--
-- Name: agent_scan_submissions agent_scan_submissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_scan_submissions
    ADD CONSTRAINT agent_scan_submissions_pkey PRIMARY KEY (id);


--
-- Name: agent_telemetry agent_telemetry_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_telemetry
    ADD CONSTRAINT agent_telemetry_pkey PRIMARY KEY (id);


--
-- Name: alembic_version alembic_version_pkc; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);


--
-- Name: ap_analyses ap_analyses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ap_analyses
    ADD CONSTRAINT ap_analyses_pkey PRIMARY KEY (id);


--
-- Name: ap_paths ap_paths_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ap_paths
    ADD CONSTRAINT ap_paths_pkey PRIMARY KEY (id);


--
-- Name: api_keys api_keys_key_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_key_hash_key UNIQUE (key_hash);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);


--
-- Name: apm_reports apm_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.apm_reports
    ADD CONSTRAINT apm_reports_pkey PRIMARY KEY (id);


--
-- Name: arch_builder_components arch_builder_components_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.arch_builder_components
    ADD CONSTRAINT arch_builder_components_pkey PRIMARY KEY (id);


--
-- Name: arch_builder_designs arch_builder_designs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.arch_builder_designs
    ADD CONSTRAINT arch_builder_designs_pkey PRIMARY KEY (id);


--
-- Name: as_endpoints as_endpoints_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.as_endpoints
    ADD CONSTRAINT as_endpoints_pkey PRIMARY KEY (id);


--
-- Name: as_findings as_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.as_findings
    ADD CONSTRAINT as_findings_pkey PRIMARY KEY (id);


--
-- Name: as_scans as_scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.as_scans
    ADD CONSTRAINT as_scans_pkey PRIMARY KEY (id);


--
-- Name: ask_usage_log ask_usage_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ask_usage_log
    ADD CONSTRAINT ask_usage_log_pkey PRIMARY KEY (id);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);


--
-- Name: ba_anomalies ba_anomalies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ba_anomalies
    ADD CONSTRAINT ba_anomalies_pkey PRIMARY KEY (id);


--
-- Name: ba_baselines ba_baselines_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ba_baselines
    ADD CONSTRAINT ba_baselines_pkey PRIMARY KEY (id);


--
-- Name: ba_patterns ba_patterns_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ba_patterns
    ADD CONSTRAINT ba_patterns_pkey PRIMARY KEY (id);


--
-- Name: ca_assessments ca_assessments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ca_assessments
    ADD CONSTRAINT ca_assessments_pkey PRIMARY KEY (id);


--
-- Name: ca_controls ca_controls_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ca_controls
    ADD CONSTRAINT ca_controls_pkey PRIMARY KEY (id);


--
-- Name: ca_frameworks ca_frameworks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ca_frameworks
    ADD CONSTRAINT ca_frameworks_pkey PRIMARY KEY (id);


--
-- Name: calendar_events calendar_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_events
    ADD CONSTRAINT calendar_events_pkey PRIMARY KEY (id);


--
-- Name: central_events central_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.central_events
    ADD CONSTRAINT central_events_pkey PRIMARY KEY (id);


--
-- Name: cloud_accounts cloud_accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cloud_accounts
    ADD CONSTRAINT cloud_accounts_pkey PRIMARY KEY (id);


--
-- Name: cloud_assets cloud_assets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cloud_assets
    ADD CONSTRAINT cloud_assets_pkey PRIMARY KEY (id);


--
-- Name: cloud_dashboard_snapshots cloud_dashboard_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cloud_dashboard_snapshots
    ADD CONSTRAINT cloud_dashboard_snapshots_pkey PRIMARY KEY (id);


--
-- Name: cloud_findings cloud_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cloud_findings
    ADD CONSTRAINT cloud_findings_pkey PRIMARY KEY (id);


--
-- Name: cloud_hardener_findings cloud_hardener_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cloud_hardener_findings
    ADD CONSTRAINT cloud_hardener_findings_pkey PRIMARY KEY (id);


--
-- Name: cloud_hardener_scans cloud_hardener_scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cloud_hardener_scans
    ADD CONSTRAINT cloud_hardener_scans_pkey PRIMARY KEY (id);


--
-- Name: cloud_runtime_findings cloud_runtime_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cloud_runtime_findings
    ADD CONSTRAINT cloud_runtime_findings_pkey PRIMARY KEY (id);


--
-- Name: cloud_runtime_scans cloud_runtime_scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cloud_runtime_scans
    ADD CONSTRAINT cloud_runtime_scans_pkey PRIMARY KEY (id);


--
-- Name: code_findings code_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.code_findings
    ADD CONSTRAINT code_findings_pkey PRIMARY KEY (id);


--
-- Name: code_sbom code_sbom_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.code_sbom
    ADD CONSTRAINT code_sbom_pkey PRIMARY KEY (id);


--
-- Name: code_scans code_scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.code_scans
    ADD CONSTRAINT code_scans_pkey PRIMARY KEY (id);


--
-- Name: compliance_assessments compliance_assessments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_assessments
    ADD CONSTRAINT compliance_assessments_pkey PRIMARY KEY (id);


--
-- Name: compliance_fabric_controls compliance_fabric_controls_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_fabric_controls
    ADD CONSTRAINT compliance_fabric_controls_pkey PRIMARY KEY (id);


--
-- Name: compliance_fabric_reports compliance_fabric_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_fabric_reports
    ADD CONSTRAINT compliance_fabric_reports_pkey PRIMARY KEY (id);


--
-- Name: compliance_results compliance_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_results
    ADD CONSTRAINT compliance_results_pkey PRIMARY KEY (id);


--
-- Name: cs_recommendations cs_recommendations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cs_recommendations
    ADD CONSTRAINT cs_recommendations_pkey PRIMARY KEY (id);


--
-- Name: cs_resources cs_resources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cs_resources
    ADD CONSTRAINT cs_resources_pkey PRIMARY KEY (id);


--
-- Name: cve_sync_logs cve_sync_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cve_sync_logs
    ADD CONSTRAINT cve_sync_logs_pkey PRIMARY KEY (id);


--
-- Name: dd_baselines dd_baselines_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dd_baselines
    ADD CONSTRAINT dd_baselines_pkey PRIMARY KEY (id);


--
-- Name: dd_drifts dd_drifts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dd_drifts
    ADD CONSTRAINT dd_drifts_pkey PRIMARY KEY (id);


--
-- Name: dd_scans dd_scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dd_scans
    ADD CONSTRAINT dd_scans_pkey PRIMARY KEY (id);


--
-- Name: defense_actions defense_actions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.defense_actions
    ADD CONSTRAINT defense_actions_pkey PRIMARY KEY (id);


--
-- Name: defense_mesh_pillars defense_mesh_pillars_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.defense_mesh_pillars
    ADD CONSTRAINT defense_mesh_pillars_pkey PRIMARY KEY (id);


--
-- Name: defense_mesh_recommendations defense_mesh_recommendations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.defense_mesh_recommendations
    ADD CONSTRAINT defense_mesh_recommendations_pkey PRIMARY KEY (id);


--
-- Name: defense_mesh_reports defense_mesh_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.defense_mesh_reports
    ADD CONSTRAINT defense_mesh_reports_pkey PRIMARY KEY (id);


--
-- Name: defense_playbooks defense_playbooks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.defense_playbooks
    ADD CONSTRAINT defense_playbooks_pkey PRIMARY KEY (id);


--
-- Name: device_risk_score_history device_risk_score_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_risk_score_history
    ADD CONSTRAINT device_risk_score_history_pkey PRIMARY KEY (id);


--
-- Name: device_risk_scores device_risk_scores_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_risk_scores
    ADD CONSTRAINT device_risk_scores_pkey PRIMARY KEY (id);


--
-- Name: device_tags device_tags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_tags
    ADD CONSTRAINT device_tags_pkey PRIMARY KEY (id);


--
-- Name: digital_twin_v2_anomalies digital_twin_v2_anomalies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.digital_twin_v2_anomalies
    ADD CONSTRAINT digital_twin_v2_anomalies_pkey PRIMARY KEY (id);


--
-- Name: digital_twin_v2_devices digital_twin_v2_devices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.digital_twin_v2_devices
    ADD CONSTRAINT digital_twin_v2_devices_pkey PRIMARY KEY (id);


--
-- Name: digital_twin_v2_environments digital_twin_v2_environments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.digital_twin_v2_environments
    ADD CONSTRAINT digital_twin_v2_environments_pkey PRIMARY KEY (id);


--
-- Name: dspm_datastores dspm_datastores_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dspm_datastores
    ADD CONSTRAINT dspm_datastores_pkey PRIMARY KEY (id);


--
-- Name: dspm_findings dspm_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dspm_findings
    ADD CONSTRAINT dspm_findings_pkey PRIMARY KEY (id);


--
-- Name: dspm_scans dspm_scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dspm_scans
    ADD CONSTRAINT dspm_scans_pkey PRIMARY KEY (id);


--
-- Name: endpoint_findings endpoint_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_findings
    ADD CONSTRAINT endpoint_findings_pkey PRIMARY KEY (id);


--
-- Name: endpoint_scans endpoint_scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_scans
    ADD CONSTRAINT endpoint_scans_pkey PRIMARY KEY (id);


--
-- Name: enterprise_reports enterprise_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enterprise_reports
    ADD CONSTRAINT enterprise_reports_pkey PRIMARY KEY (id);


--
-- Name: explain_results explain_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.explain_results
    ADD CONSTRAINT explain_results_pkey PRIMARY KEY (id);


--
-- Name: findings findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_pkey PRIMARY KEY (id);


--
-- Name: forecast_alerts forecast_alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.forecast_alerts
    ADD CONSTRAINT forecast_alerts_pkey PRIMARY KEY (id);


--
-- Name: forensic_artifacts forensic_artifacts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.forensic_artifacts
    ADD CONSTRAINT forensic_artifacts_pkey PRIMARY KEY (id);


--
-- Name: forensic_cases forensic_cases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.forensic_cases
    ADD CONSTRAINT forensic_cases_pkey PRIMARY KEY (id);


--
-- Name: forensic_timeline forensic_timeline_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.forensic_timeline
    ADD CONSTRAINT forensic_timeline_pkey PRIMARY KEY (id);


--
-- Name: iam_exposure_findings iam_exposure_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.iam_exposure_findings
    ADD CONSTRAINT iam_exposure_findings_pkey PRIMARY KEY (id);


--
-- Name: iam_exposure_scans iam_exposure_scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.iam_exposure_scans
    ADD CONSTRAINT iam_exposure_scans_pkey PRIMARY KEY (id);


--
-- Name: identity_guardian_alerts identity_guardian_alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_guardian_alerts
    ADD CONSTRAINT identity_guardian_alerts_pkey PRIMARY KEY (id);


--
-- Name: identity_guardian_signals identity_guardian_signals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_guardian_signals
    ADD CONSTRAINT identity_guardian_signals_pkey PRIMARY KEY (id);


--
-- Name: ig_edges ig_edges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ig_edges
    ADD CONSTRAINT ig_edges_pkey PRIMARY KEY (id);


--
-- Name: ig_identities ig_identities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ig_identities
    ADD CONSTRAINT ig_identities_pkey PRIMARY KEY (id);


--
-- Name: ig_risks ig_risks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ig_risks
    ADD CONSTRAINT ig_risks_pkey PRIMARY KEY (id);


--
-- Name: ioc_entries ioc_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_entries
    ADD CONSTRAINT ioc_entries_pkey PRIMARY KEY (id);


--
-- Name: ioc_feeds ioc_feeds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_feeds
    ADD CONSTRAINT ioc_feeds_pkey PRIMARY KEY (id);


--
-- Name: ir_incidents ir_incidents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ir_incidents
    ADD CONSTRAINT ir_incidents_pkey PRIMARY KEY (id);


--
-- Name: ir_tasks ir_tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ir_tasks
    ADD CONSTRAINT ir_tasks_pkey PRIMARY KEY (id);


--
-- Name: itdr_findings itdr_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itdr_findings
    ADD CONSTRAINT itdr_findings_pkey PRIMARY KEY (id);


--
-- Name: itdr_scans itdr_scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itdr_scans
    ADD CONSTRAINT itdr_scans_pkey PRIMARY KEY (id);


--
-- Name: k8s_findings k8s_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.k8s_findings
    ADD CONSTRAINT k8s_findings_pkey PRIMARY KEY (id);


--
-- Name: k8s_scans k8s_scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.k8s_scans
    ADD CONSTRAINT k8s_scans_pkey PRIMARY KEY (id);


--
-- Name: kev_catalog kev_catalog_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kev_catalog
    ADD CONSTRAINT kev_catalog_pkey PRIMARY KEY (cve_id);


--
-- Name: live_cves live_cves_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.live_cves
    ADD CONSTRAINT live_cves_pkey PRIMARY KEY (cve_id);


--
-- Name: log_analysis_reports log_analysis_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.log_analysis_reports
    ADD CONSTRAINT log_analysis_reports_pkey PRIMARY KEY (id);


--
-- Name: metrics_reports metrics_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metrics_reports
    ADD CONSTRAINT metrics_reports_pkey PRIMARY KEY (id);


--
-- Name: mitre_techniques mitre_techniques_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_techniques
    ADD CONSTRAINT mitre_techniques_pkey PRIMARY KEY (technique_id);


--
-- Name: ml_anomaly_detections ml_anomaly_detections_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ml_anomaly_detections
    ADD CONSTRAINT ml_anomaly_detections_pkey PRIMARY KEY (id);


--
-- Name: ml_anomaly_model_versions ml_anomaly_model_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ml_anomaly_model_versions
    ADD CONSTRAINT ml_anomaly_model_versions_pkey PRIMARY KEY (id);


--
-- Name: ml_anomaly_model_versions ml_anomaly_model_versions_version_tag_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ml_anomaly_model_versions
    ADD CONSTRAINT ml_anomaly_model_versions_version_tag_key UNIQUE (version_tag);


--
-- Name: mp_installs mp_installs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mp_installs
    ADD CONSTRAINT mp_installs_pkey PRIMARY KEY (id);


--
-- Name: mp_plugins mp_plugins_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mp_plugins
    ADD CONSTRAINT mp_plugins_pkey PRIMARY KEY (id);


--
-- Name: mp_plugins mp_plugins_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mp_plugins
    ADD CONSTRAINT mp_plugins_slug_key UNIQUE (slug);


--
-- Name: mp_reviews mp_reviews_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mp_reviews
    ADD CONSTRAINT mp_reviews_pkey PRIMARY KEY (id);


--
-- Name: multicloud_scale_reports multicloud_scale_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.multicloud_scale_reports
    ADD CONSTRAINT multicloud_scale_reports_pkey PRIMARY KEY (id);


--
-- Name: network_exposure_assets network_exposure_assets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.network_exposure_assets
    ADD CONSTRAINT network_exposure_assets_pkey PRIMARY KEY (id);


--
-- Name: network_exposure_paths network_exposure_paths_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.network_exposure_paths
    ADD CONSTRAINT network_exposure_paths_pkey PRIMARY KEY (id);


--
-- Name: network_exposure_scans network_exposure_scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.network_exposure_scans
    ADD CONSTRAINT network_exposure_scans_pkey PRIMARY KEY (id);


--
-- Name: nv_edges nv_edges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nv_edges
    ADD CONSTRAINT nv_edges_pkey PRIMARY KEY (id);


--
-- Name: nv_issues nv_issues_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nv_issues
    ADD CONSTRAINT nv_issues_pkey PRIMARY KEY (id);


--
-- Name: nv_nodes nv_nodes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nv_nodes
    ADD CONSTRAINT nv_nodes_pkey PRIMARY KEY (id);


--
-- Name: ot_devices ot_devices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ot_devices
    ADD CONSTRAINT ot_devices_pkey PRIMARY KEY (id);


--
-- Name: ot_findings ot_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ot_findings
    ADD CONSTRAINT ot_findings_pkey PRIMARY KEY (id);


--
-- Name: ot_scans ot_scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ot_scans
    ADD CONSTRAINT ot_scans_pkey PRIMARY KEY (id);


--
-- Name: password_reset_tokens password_reset_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_pkey PRIMARY KEY (id);


--
-- Name: patch_brain_items patch_brain_items_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_brain_items
    ADD CONSTRAINT patch_brain_items_pkey PRIMARY KEY (id);


--
-- Name: patch_brain_sessions patch_brain_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_brain_sessions
    ADD CONSTRAINT patch_brain_sessions_pkey PRIMARY KEY (id);


--
-- Name: permissions permissions_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_name_key UNIQUE (name);


--
-- Name: permissions permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_pkey PRIMARY KEY (id);


--
-- Name: policy_brain_policies policy_brain_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policy_brain_policies
    ADD CONSTRAINT policy_brain_policies_pkey PRIMARY KEY (id);


--
-- Name: policy_brain_sections policy_brain_sections_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policy_brain_sections
    ADD CONSTRAINT policy_brain_sections_pkey PRIMARY KEY (id);


--
-- Name: predict_alerts predict_alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.predict_alerts
    ADD CONSTRAINT predict_alerts_pkey PRIMARY KEY (id);


--
-- Name: protocol_scans protocol_scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protocol_scans
    ADD CONSTRAINT protocol_scans_pkey PRIMARY KEY (id);


--
-- Name: push_subscriptions push_subscriptions_endpoint_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_subscriptions
    ADD CONSTRAINT push_subscriptions_endpoint_key UNIQUE (endpoint);


--
-- Name: push_subscriptions push_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_subscriptions
    ADD CONSTRAINT push_subscriptions_pkey PRIMARY KEY (id);


--
-- Name: rbac_assessments rbac_assessments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rbac_assessments
    ADD CONSTRAINT rbac_assessments_pkey PRIMARY KEY (id);


--
-- Name: rbac_roles rbac_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rbac_roles
    ADD CONSTRAINT rbac_roles_pkey PRIMARY KEY (id);


--
-- Name: re_assets re_assets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.re_assets
    ADD CONSTRAINT re_assets_pkey PRIMARY KEY (id);


--
-- Name: re_plans re_plans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.re_plans
    ADD CONSTRAINT re_plans_pkey PRIMARY KEY (id);


--
-- Name: re_tests re_tests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.re_tests
    ADD CONSTRAINT re_tests_pkey PRIMARY KEY (id);


--
-- Name: real_scan_results real_scan_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.real_scan_results
    ADD CONSTRAINT real_scan_results_pkey PRIMARY KEY (id);


--
-- Name: realtime_snapshots realtime_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.realtime_snapshots
    ADD CONSTRAINT realtime_snapshots_pkey PRIMARY KEY (id);


--
-- Name: remediation_kb remediation_kb_attack_type_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_kb
    ADD CONSTRAINT remediation_kb_attack_type_key UNIQUE (attack_type);


--
-- Name: remediation_kb remediation_kb_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_kb
    ADD CONSTRAINT remediation_kb_pkey PRIMARY KEY (id);


--
-- Name: response_history response_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.response_history
    ADD CONSTRAINT response_history_pkey PRIMARY KEY (id);


--
-- Name: response_thresholds response_thresholds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.response_thresholds
    ADD CONSTRAINT response_thresholds_pkey PRIMARY KEY (id);


--
-- Name: risk_narratives risk_narratives_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.risk_narratives
    ADD CONSTRAINT risk_narratives_pkey PRIMARY KEY (id);


--
-- Name: role_permissions role_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_pkey PRIMARY KEY (role_id, permission_id);


--
-- Name: roles roles_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_name_key UNIQUE (name);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);


--
-- Name: rt_attacks rt_attacks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rt_attacks
    ADD CONSTRAINT rt_attacks_pkey PRIMARY KEY (id);


--
-- Name: rt_campaigns rt_campaigns_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rt_campaigns
    ADD CONSTRAINT rt_campaigns_pkey PRIMARY KEY (id);


--
-- Name: runtime_protection_findings runtime_protection_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.runtime_protection_findings
    ADD CONSTRAINT runtime_protection_findings_pkey PRIMARY KEY (id);


--
-- Name: runtime_protection_scans runtime_protection_scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.runtime_protection_scans
    ADD CONSTRAINT runtime_protection_scans_pkey PRIMARY KEY (id);


--
-- Name: sandbox_analyses sandbox_analyses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sandbox_analyses
    ADD CONSTRAINT sandbox_analyses_pkey PRIMARY KEY (id);


--
-- Name: sandbox_findings sandbox_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sandbox_findings
    ADD CONSTRAINT sandbox_findings_pkey PRIMARY KEY (id);


--
-- Name: sc_components sc_components_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sc_components
    ADD CONSTRAINT sc_components_pkey PRIMARY KEY (id);


--
-- Name: sc_sboms sc_sboms_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sc_sboms
    ADD CONSTRAINT sc_sboms_pkey PRIMARY KEY (id);


--
-- Name: sc_vulns sc_vulns_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sc_vulns
    ADD CONSTRAINT sc_vulns_pkey PRIMARY KEY (id);


--
-- Name: scans scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_pkey PRIMARY KEY (id);


--
-- Name: score_results score_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.score_results
    ADD CONSTRAINT score_results_pkey PRIMARY KEY (id);


--
-- Name: siem_events siem_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.siem_events
    ADD CONSTRAINT siem_events_pkey PRIMARY KEY (id);


--
-- Name: siem_incidents siem_incidents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.siem_incidents
    ADD CONSTRAINT siem_incidents_pkey PRIMARY KEY (id);


--
-- Name: siem_reports siem_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.siem_reports
    ADD CONSTRAINT siem_reports_pkey PRIMARY KEY (id);


--
-- Name: siem_rules siem_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.siem_rules
    ADD CONSTRAINT siem_rules_pkey PRIMARY KEY (id);


--
-- Name: soc_twin_actions soc_twin_actions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.soc_twin_actions
    ADD CONSTRAINT soc_twin_actions_pkey PRIMARY KEY (id);


--
-- Name: soc_twin_sessions soc_twin_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.soc_twin_sessions
    ADD CONSTRAINT soc_twin_sessions_pkey PRIMARY KEY (id);


--
-- Name: sso_providers sso_providers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sso_providers
    ADD CONSTRAINT sso_providers_pkey PRIMARY KEY (id);


--
-- Name: synthetic_checks synthetic_checks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.synthetic_checks
    ADD CONSTRAINT synthetic_checks_pkey PRIMARY KEY (id);


--
-- Name: te_clusters te_clusters_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.te_clusters
    ADD CONSTRAINT te_clusters_pkey PRIMARY KEY (id);


--
-- Name: te_events te_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.te_events
    ADD CONSTRAINT te_events_pkey PRIMARY KEY (id);


--
-- Name: tenant_assessments tenant_assessments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_assessments
    ADD CONSTRAINT tenant_assessments_pkey PRIMARY KEY (id);


--
-- Name: terminal_audit_log terminal_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.terminal_audit_log
    ADD CONSTRAINT terminal_audit_log_pkey PRIMARY KEY (id);


--
-- Name: terminal_sessions terminal_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.terminal_sessions
    ADD CONSTRAINT terminal_sessions_pkey PRIMARY KEY (id);


--
-- Name: terminal_sessions terminal_sessions_session_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.terminal_sessions
    ADD CONSTRAINT terminal_sessions_session_key_key UNIQUE (session_key);


--
-- Name: threat_intel_feeds threat_intel_feeds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_intel_feeds
    ADD CONSTRAINT threat_intel_feeds_pkey PRIMARY KEY (id);


--
-- Name: threat_intel_iocs threat_intel_iocs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_intel_iocs
    ADD CONSTRAINT threat_intel_iocs_pkey PRIMARY KEY (id);


--
-- Name: threat_matches threat_matches_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_matches
    ADD CONSTRAINT threat_matches_pkey PRIMARY KEY (id);


--
-- Name: threat_radar_reports threat_radar_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_radar_reports
    ADD CONSTRAINT threat_radar_reports_pkey PRIMARY KEY (id);


--
-- Name: threat_radar_threats threat_radar_threats_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_radar_threats
    ADD CONSTRAINT threat_radar_threats_pkey PRIMARY KEY (id);


--
-- Name: timeline_events timeline_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.timeline_events
    ADD CONSTRAINT timeline_events_pkey PRIMARY KEY (id);


--
-- Name: twin_edges twin_edges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.twin_edges
    ADD CONSTRAINT twin_edges_pkey PRIMARY KEY (id);


--
-- Name: twin_nodes twin_nodes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.twin_nodes
    ADD CONSTRAINT twin_nodes_pkey PRIMARY KEY (id);


--
-- Name: twin_snapshots twin_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.twin_snapshots
    ADD CONSTRAINT twin_snapshots_pkey PRIMARY KEY (id);


--
-- Name: agent_scan_submissions uq_agent_scan_user_scan_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_scan_submissions
    ADD CONSTRAINT uq_agent_scan_user_scan_id UNIQUE (user_id, scan_id);


--
-- Name: ask_usage_log uq_ask_usage_user_date; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ask_usage_log
    ADD CONSTRAINT uq_ask_usage_user_date UNIQUE (user_id, date);


--
-- Name: device_risk_scores uq_device_risk_user_entity; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_risk_scores
    ADD CONSTRAINT uq_device_risk_user_entity UNIQUE (user_id, entity, entity_type);


--
-- Name: forecast_alerts uq_forecast_active; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.forecast_alerts
    ADD CONSTRAINT uq_forecast_active UNIQUE (user_id, entity, threshold_name, status);


--
-- Name: response_thresholds uq_threshold_user_name; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.response_thresholds
    ADD CONSTRAINT uq_threshold_user_name UNIQUE (user_id, name);


--
-- Name: user_roles user_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_pkey PRIMARY KEY (id);


--
-- Name: user_settings user_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_settings
    ADD CONSTRAINT user_settings_pkey PRIMARY KEY (id);


--
-- Name: user_settings user_settings_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_settings
    ADD CONSTRAINT user_settings_user_id_key UNIQUE (user_id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_stripe_customer_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_stripe_customer_id_key UNIQUE (stripe_customer_id);


--
-- Name: users users_stripe_subscription_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_stripe_subscription_id_key UNIQUE (stripe_subscription_id);


--
-- Name: watch_alerts watch_alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.watch_alerts
    ADD CONSTRAINT watch_alerts_pkey PRIMARY KEY (id);


--
-- Name: watch_baselines watch_baselines_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.watch_baselines
    ADD CONSTRAINT watch_baselines_pkey PRIMARY KEY (id);


--
-- Name: zt_access_log zt_access_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.zt_access_log
    ADD CONSTRAINT zt_access_log_pkey PRIMARY KEY (id);


--
-- Name: zt_device_trust zt_device_trust_device_ip_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.zt_device_trust
    ADD CONSTRAINT zt_device_trust_device_ip_key UNIQUE (device_ip);


--
-- Name: zt_device_trust zt_device_trust_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.zt_device_trust
    ADD CONSTRAINT zt_device_trust_pkey PRIMARY KEY (id);


--
-- Name: zt_policies zt_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.zt_policies
    ADD CONSTRAINT zt_policies_pkey PRIMARY KEY (id);


--
-- Name: ix_agent_api_keys_key_prefix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_agent_api_keys_key_prefix ON public.agent_api_keys USING btree (key_prefix);


--
-- Name: ix_agent_api_keys_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_agent_api_keys_user_id ON public.agent_api_keys USING btree (user_id);


--
-- Name: ix_agent_devices_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_agent_devices_user_id ON public.agent_devices USING btree (user_id);


--
-- Name: ix_agent_keys_prefix_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_agent_keys_prefix_enabled ON public.agent_api_keys USING btree (key_prefix, enabled);


--
-- Name: ix_agent_keys_user_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_agent_keys_user_enabled ON public.agent_api_keys USING btree (user_id, enabled);


--
-- Name: ix_agent_scan_sub_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_agent_scan_sub_user_id ON public.agent_scan_submissions USING btree (user_id);


--
-- Name: ix_agent_scan_submissions_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_agent_scan_submissions_user_id ON public.agent_scan_submissions USING btree (user_id);


--
-- Name: ix_agent_telemetry_agent_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_agent_telemetry_agent_id ON public.agent_telemetry USING btree (agent_id);


--
-- Name: ix_agent_telemetry_agent_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_agent_telemetry_agent_time ON public.agent_telemetry USING btree (agent_id, collected_at);


--
-- Name: ix_agent_telemetry_collected_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_agent_telemetry_collected_at ON public.agent_telemetry USING btree (collected_at);


--
-- Name: ix_agent_telemetry_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_agent_telemetry_user_id ON public.agent_telemetry USING btree (user_id);


--
-- Name: ix_ask_usage_log_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ask_usage_log_user_id ON public.ask_usage_log USING btree (user_id);


--
-- Name: ix_calendar_events_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_calendar_events_user_id ON public.calendar_events USING btree (user_id);


--
-- Name: ix_central_events_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_central_events_created_at ON public.central_events USING btree (created_at);


--
-- Name: ix_central_events_created_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_central_events_created_severity ON public.central_events USING btree (created_at, severity);


--
-- Name: ix_central_events_entity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_central_events_entity ON public.central_events USING btree (entity);


--
-- Name: ix_central_events_entity_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_central_events_entity_created ON public.central_events USING btree (entity, created_at);


--
-- Name: ix_central_events_event_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_central_events_event_type ON public.central_events USING btree (event_type);


--
-- Name: ix_central_events_module_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_central_events_module_type ON public.central_events USING btree (source_module, event_type);


--
-- Name: ix_central_events_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_central_events_severity ON public.central_events USING btree (severity);


--
-- Name: ix_central_events_source_module; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_central_events_source_module ON public.central_events USING btree (source_module);


--
-- Name: ix_central_events_user_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_central_events_user_created ON public.central_events USING btree (user_id, created_at);


--
-- Name: ix_central_events_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_central_events_user_id ON public.central_events USING btree (user_id);


--
-- Name: ix_device_risk_score_history_entity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_device_risk_score_history_entity ON public.device_risk_score_history USING btree (entity);


--
-- Name: ix_device_risk_score_history_snapshot_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_device_risk_score_history_snapshot_at ON public.device_risk_score_history USING btree (snapshot_at);


--
-- Name: ix_device_risk_score_history_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_device_risk_score_history_user_id ON public.device_risk_score_history USING btree (user_id);


--
-- Name: ix_device_risk_score_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_device_risk_score_updated ON public.device_risk_scores USING btree (score, last_updated_at);


--
-- Name: ix_device_risk_scores_entity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_device_risk_scores_entity ON public.device_risk_scores USING btree (entity);


--
-- Name: ix_device_risk_scores_last_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_device_risk_scores_last_updated_at ON public.device_risk_scores USING btree (last_updated_at);


--
-- Name: ix_device_risk_scores_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_device_risk_scores_user_id ON public.device_risk_scores USING btree (user_id);


--
-- Name: ix_device_risk_user_score; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_device_risk_user_score ON public.device_risk_scores USING btree (user_id, score);


--
-- Name: ix_findings_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_findings_scan_id ON public.findings USING btree (scan_id);


--
-- Name: ix_forecast_alerts_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_forecast_alerts_created_at ON public.forecast_alerts USING btree (created_at);


--
-- Name: ix_forecast_alerts_entity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_forecast_alerts_entity ON public.forecast_alerts USING btree (entity);


--
-- Name: ix_forecast_alerts_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_forecast_alerts_user_id ON public.forecast_alerts USING btree (user_id);


--
-- Name: ix_forecast_user_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_forecast_user_status ON public.forecast_alerts USING btree (user_id, status);


--
-- Name: ix_history_cooldown; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_history_cooldown ON public.response_history USING btree (user_id, entity, playbook_id, fired_at);


--
-- Name: ix_history_entity_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_history_entity_time ON public.device_risk_score_history USING btree (user_id, entity, entity_type, snapshot_at);


--
-- Name: ix_history_snapshot_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_history_snapshot_at ON public.device_risk_score_history USING btree (snapshot_at);


--
-- Name: ix_kev_catalog_date_added; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_kev_catalog_date_added ON public.kev_catalog USING btree (date_added);


--
-- Name: ix_kev_catalog_known_ransomware_use; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_kev_catalog_known_ransomware_use ON public.kev_catalog USING btree (known_ransomware_use);


--
-- Name: ix_live_cves_cvss; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_live_cves_cvss ON public.live_cves USING btree (cvss_score);


--
-- Name: ix_live_cves_published; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_live_cves_published ON public.live_cves USING btree (published);


--
-- Name: ix_live_cves_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_live_cves_severity ON public.live_cves USING btree (severity);


--
-- Name: ix_password_reset_tokens_token; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_password_reset_tokens_token ON public.password_reset_tokens USING btree (token);


--
-- Name: ix_push_subscriptions_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_push_subscriptions_user_id ON public.push_subscriptions USING btree (user_id);


--
-- Name: ix_push_user_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_push_user_enabled ON public.push_subscriptions USING btree (user_id, enabled);


--
-- Name: ix_real_scan_results_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_real_scan_results_user_id ON public.real_scan_results USING btree (user_id);


--
-- Name: ix_response_history_fired_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_response_history_fired_at ON public.response_history USING btree (fired_at);


--
-- Name: ix_response_history_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_response_history_user_id ON public.response_history USING btree (user_id);


--
-- Name: ix_response_thresholds_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_response_thresholds_user_id ON public.response_thresholds USING btree (user_id);


--
-- Name: ix_scans_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scans_user_id ON public.scans USING btree (user_id);


--
-- Name: ix_threshold_user_score; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_threshold_user_score ON public.response_thresholds USING btree (user_id, min_score);


--
-- Name: ix_users_email; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_users_email ON public.users USING btree (email);


--
-- Name: agent_api_keys agent_api_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_api_keys
    ADD CONSTRAINT agent_api_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: agent_scan_submissions agent_scan_submissions_agent_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_scan_submissions
    ADD CONSTRAINT agent_scan_submissions_agent_key_id_fkey FOREIGN KEY (agent_key_id) REFERENCES public.agent_api_keys(id);


--
-- Name: ap_analyses ap_analyses_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ap_analyses
    ADD CONSTRAINT ap_analyses_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: ap_paths ap_paths_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ap_paths
    ADD CONSTRAINT ap_paths_analysis_id_fkey FOREIGN KEY (analysis_id) REFERENCES public.ap_analyses(id);


--
-- Name: api_keys api_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: arch_builder_components arch_builder_components_design_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.arch_builder_components
    ADD CONSTRAINT arch_builder_components_design_id_fkey FOREIGN KEY (design_id) REFERENCES public.arch_builder_designs(id);


--
-- Name: as_findings as_findings_endpoint_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.as_findings
    ADD CONSTRAINT as_findings_endpoint_id_fkey FOREIGN KEY (endpoint_id) REFERENCES public.as_endpoints(id);


--
-- Name: ask_usage_log ask_usage_log_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ask_usage_log
    ADD CONSTRAINT ask_usage_log_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: audit_log audit_log_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: ba_anomalies ba_anomalies_baseline_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ba_anomalies
    ADD CONSTRAINT ba_anomalies_baseline_id_fkey FOREIGN KEY (baseline_id) REFERENCES public.ba_baselines(id);


--
-- Name: ba_patterns ba_patterns_baseline_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ba_patterns
    ADD CONSTRAINT ba_patterns_baseline_id_fkey FOREIGN KEY (baseline_id) REFERENCES public.ba_baselines(id);


--
-- Name: ca_assessments ca_assessments_framework_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ca_assessments
    ADD CONSTRAINT ca_assessments_framework_id_fkey FOREIGN KEY (framework_id) REFERENCES public.ca_frameworks(id);


--
-- Name: ca_controls ca_controls_framework_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ca_controls
    ADD CONSTRAINT ca_controls_framework_id_fkey FOREIGN KEY (framework_id) REFERENCES public.ca_frameworks(id);


--
-- Name: central_events central_events_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.central_events
    ADD CONSTRAINT central_events_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: cloud_accounts cloud_accounts_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cloud_accounts
    ADD CONSTRAINT cloud_accounts_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: cloud_assets cloud_assets_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cloud_assets
    ADD CONSTRAINT cloud_assets_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.cloud_accounts(id);


--
-- Name: cloud_findings cloud_findings_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cloud_findings
    ADD CONSTRAINT cloud_findings_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.cloud_accounts(id);


--
-- Name: cloud_findings cloud_findings_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cloud_findings
    ADD CONSTRAINT cloud_findings_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.cloud_assets(id);


--
-- Name: cloud_hardener_findings cloud_hardener_findings_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cloud_hardener_findings
    ADD CONSTRAINT cloud_hardener_findings_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.cloud_hardener_scans(id);


--
-- Name: cloud_runtime_findings cloud_runtime_findings_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cloud_runtime_findings
    ADD CONSTRAINT cloud_runtime_findings_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.cloud_runtime_scans(id);


--
-- Name: code_findings code_findings_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.code_findings
    ADD CONSTRAINT code_findings_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.code_scans(id);


--
-- Name: code_sbom code_sbom_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.code_sbom
    ADD CONSTRAINT code_sbom_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.code_scans(id);


--
-- Name: code_scans code_scans_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.code_scans
    ADD CONSTRAINT code_scans_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: compliance_fabric_controls compliance_fabric_controls_report_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_fabric_controls
    ADD CONSTRAINT compliance_fabric_controls_report_id_fkey FOREIGN KEY (report_id) REFERENCES public.compliance_fabric_reports(id);


--
-- Name: compliance_results compliance_results_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_results
    ADD CONSTRAINT compliance_results_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id);


--
-- Name: compliance_results compliance_results_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_results
    ADD CONSTRAINT compliance_results_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: cs_recommendations cs_recommendations_resource_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cs_recommendations
    ADD CONSTRAINT cs_recommendations_resource_id_fkey FOREIGN KEY (resource_id) REFERENCES public.cs_resources(id);


--
-- Name: dd_drifts dd_drifts_baseline_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dd_drifts
    ADD CONSTRAINT dd_drifts_baseline_id_fkey FOREIGN KEY (baseline_id) REFERENCES public.dd_baselines(id);


--
-- Name: defense_actions defense_actions_playbook_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.defense_actions
    ADD CONSTRAINT defense_actions_playbook_id_fkey FOREIGN KEY (playbook_id) REFERENCES public.defense_playbooks(id);


--
-- Name: defense_mesh_pillars defense_mesh_pillars_report_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.defense_mesh_pillars
    ADD CONSTRAINT defense_mesh_pillars_report_id_fkey FOREIGN KEY (report_id) REFERENCES public.defense_mesh_reports(id);


--
-- Name: defense_mesh_recommendations defense_mesh_recommendations_report_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.defense_mesh_recommendations
    ADD CONSTRAINT defense_mesh_recommendations_report_id_fkey FOREIGN KEY (report_id) REFERENCES public.defense_mesh_reports(id);


--
-- Name: defense_playbooks defense_playbooks_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.defense_playbooks
    ADD CONSTRAINT defense_playbooks_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: device_risk_score_history device_risk_score_history_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_risk_score_history
    ADD CONSTRAINT device_risk_score_history_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: device_risk_scores device_risk_scores_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_risk_scores
    ADD CONSTRAINT device_risk_scores_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: device_tags device_tags_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_tags
    ADD CONSTRAINT device_tags_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: digital_twin_v2_anomalies digital_twin_v2_anomalies_env_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.digital_twin_v2_anomalies
    ADD CONSTRAINT digital_twin_v2_anomalies_env_id_fkey FOREIGN KEY (env_id) REFERENCES public.digital_twin_v2_environments(id);


--
-- Name: digital_twin_v2_devices digital_twin_v2_devices_env_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.digital_twin_v2_devices
    ADD CONSTRAINT digital_twin_v2_devices_env_id_fkey FOREIGN KEY (env_id) REFERENCES public.digital_twin_v2_environments(id);


--
-- Name: dspm_findings dspm_findings_datastore_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dspm_findings
    ADD CONSTRAINT dspm_findings_datastore_id_fkey FOREIGN KEY (datastore_id) REFERENCES public.dspm_datastores(id);


--
-- Name: endpoint_findings endpoint_findings_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_findings
    ADD CONSTRAINT endpoint_findings_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.endpoint_scans(id);


--
-- Name: explain_results explain_results_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.explain_results
    ADD CONSTRAINT explain_results_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id);


--
-- Name: explain_results explain_results_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.explain_results
    ADD CONSTRAINT explain_results_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id);


--
-- Name: findings findings_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id);


--
-- Name: forecast_alerts forecast_alerts_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.forecast_alerts
    ADD CONSTRAINT forecast_alerts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: forensic_artifacts forensic_artifacts_case_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.forensic_artifacts
    ADD CONSTRAINT forensic_artifacts_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.forensic_cases(id);


--
-- Name: forensic_timeline forensic_timeline_case_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.forensic_timeline
    ADD CONSTRAINT forensic_timeline_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.forensic_cases(id);


--
-- Name: iam_exposure_findings iam_exposure_findings_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.iam_exposure_findings
    ADD CONSTRAINT iam_exposure_findings_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.iam_exposure_scans(id);


--
-- Name: identity_guardian_signals identity_guardian_signals_alert_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_guardian_signals
    ADD CONSTRAINT identity_guardian_signals_alert_id_fkey FOREIGN KEY (alert_id) REFERENCES public.identity_guardian_alerts(id);


--
-- Name: ig_edges ig_edges_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ig_edges
    ADD CONSTRAINT ig_edges_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.ig_identities(id);


--
-- Name: ig_edges ig_edges_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ig_edges
    ADD CONSTRAINT ig_edges_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.ig_identities(id);


--
-- Name: ig_risks ig_risks_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ig_risks
    ADD CONSTRAINT ig_risks_identity_id_fkey FOREIGN KEY (identity_id) REFERENCES public.ig_identities(id);


--
-- Name: ioc_entries ioc_entries_feed_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_entries
    ADD CONSTRAINT ioc_entries_feed_id_fkey FOREIGN KEY (feed_id) REFERENCES public.ioc_feeds(id);


--
-- Name: ir_incidents ir_incidents_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ir_incidents
    ADD CONSTRAINT ir_incidents_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: ir_tasks ir_tasks_incident_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ir_tasks
    ADD CONSTRAINT ir_tasks_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES public.ir_incidents(id);


--
-- Name: itdr_findings itdr_findings_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itdr_findings
    ADD CONSTRAINT itdr_findings_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.itdr_scans(id);


--
-- Name: k8s_findings k8s_findings_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.k8s_findings
    ADD CONSTRAINT k8s_findings_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.k8s_scans(id);


--
-- Name: ml_anomaly_detections ml_anomaly_detections_model_version_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ml_anomaly_detections
    ADD CONSTRAINT ml_anomaly_detections_model_version_id_fkey FOREIGN KEY (model_version_id) REFERENCES public.ml_anomaly_model_versions(id);


--
-- Name: ml_anomaly_detections ml_anomaly_detections_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ml_anomaly_detections
    ADD CONSTRAINT ml_anomaly_detections_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: mp_installs mp_installs_plugin_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mp_installs
    ADD CONSTRAINT mp_installs_plugin_id_fkey FOREIGN KEY (plugin_id) REFERENCES public.mp_plugins(id);


--
-- Name: mp_installs mp_installs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mp_installs
    ADD CONSTRAINT mp_installs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: mp_reviews mp_reviews_plugin_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mp_reviews
    ADD CONSTRAINT mp_reviews_plugin_id_fkey FOREIGN KEY (plugin_id) REFERENCES public.mp_plugins(id);


--
-- Name: mp_reviews mp_reviews_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mp_reviews
    ADD CONSTRAINT mp_reviews_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: network_exposure_assets network_exposure_assets_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.network_exposure_assets
    ADD CONSTRAINT network_exposure_assets_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.network_exposure_scans(id);


--
-- Name: network_exposure_paths network_exposure_paths_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.network_exposure_paths
    ADD CONSTRAINT network_exposure_paths_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.network_exposure_scans(id);


--
-- Name: nv_edges nv_edges_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nv_edges
    ADD CONSTRAINT nv_edges_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.nv_nodes(id);


--
-- Name: nv_edges nv_edges_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nv_edges
    ADD CONSTRAINT nv_edges_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.nv_nodes(id);


--
-- Name: nv_issues nv_issues_edge_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nv_issues
    ADD CONSTRAINT nv_issues_edge_id_fkey FOREIGN KEY (edge_id) REFERENCES public.nv_edges(id);


--
-- Name: nv_issues nv_issues_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nv_issues
    ADD CONSTRAINT nv_issues_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nv_nodes(id);


--
-- Name: ot_findings ot_findings_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ot_findings
    ADD CONSTRAINT ot_findings_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.ot_scans(id);


--
-- Name: ot_scans ot_scans_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ot_scans
    ADD CONSTRAINT ot_scans_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: password_reset_tokens password_reset_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: patch_brain_items patch_brain_items_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_brain_items
    ADD CONSTRAINT patch_brain_items_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.patch_brain_sessions(id);


--
-- Name: policy_brain_sections policy_brain_sections_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policy_brain_sections
    ADD CONSTRAINT policy_brain_sections_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.policy_brain_policies(id);


--
-- Name: predict_alerts predict_alerts_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.predict_alerts
    ADD CONSTRAINT predict_alerts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: protocol_scans protocol_scans_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protocol_scans
    ADD CONSTRAINT protocol_scans_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: push_subscriptions push_subscriptions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_subscriptions
    ADD CONSTRAINT push_subscriptions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: re_plans re_plans_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.re_plans
    ADD CONSTRAINT re_plans_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.re_assets(id);


--
-- Name: re_tests re_tests_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.re_tests
    ADD CONSTRAINT re_tests_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.re_assets(id);


--
-- Name: response_history response_history_playbook_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.response_history
    ADD CONSTRAINT response_history_playbook_id_fkey FOREIGN KEY (playbook_id) REFERENCES public.defense_playbooks(id);


--
-- Name: response_history response_history_threshold_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.response_history
    ADD CONSTRAINT response_history_threshold_id_fkey FOREIGN KEY (threshold_id) REFERENCES public.response_thresholds(id);


--
-- Name: response_history response_history_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.response_history
    ADD CONSTRAINT response_history_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: response_thresholds response_thresholds_playbook_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.response_thresholds
    ADD CONSTRAINT response_thresholds_playbook_id_fkey FOREIGN KEY (playbook_id) REFERENCES public.defense_playbooks(id);


--
-- Name: response_thresholds response_thresholds_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.response_thresholds
    ADD CONSTRAINT response_thresholds_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: risk_narratives risk_narratives_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.risk_narratives
    ADD CONSTRAINT risk_narratives_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: role_permissions role_permissions_permission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_permission_id_fkey FOREIGN KEY (permission_id) REFERENCES public.permissions(id);


--
-- Name: role_permissions role_permissions_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id);


--
-- Name: rt_attacks rt_attacks_campaign_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rt_attacks
    ADD CONSTRAINT rt_attacks_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES public.rt_campaigns(id);


--
-- Name: rt_campaigns rt_campaigns_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rt_campaigns
    ADD CONSTRAINT rt_campaigns_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: runtime_protection_findings runtime_protection_findings_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.runtime_protection_findings
    ADD CONSTRAINT runtime_protection_findings_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.runtime_protection_scans(id);


--
-- Name: sandbox_findings sandbox_findings_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sandbox_findings
    ADD CONSTRAINT sandbox_findings_analysis_id_fkey FOREIGN KEY (analysis_id) REFERENCES public.sandbox_analyses(id);


--
-- Name: sc_vulns sc_vulns_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sc_vulns
    ADD CONSTRAINT sc_vulns_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.sc_components(id);


--
-- Name: scans scans_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: score_results score_results_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.score_results
    ADD CONSTRAINT score_results_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id);


--
-- Name: score_results score_results_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.score_results
    ADD CONSTRAINT score_results_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: siem_events siem_events_incident_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.siem_events
    ADD CONSTRAINT siem_events_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES public.siem_incidents(id);


--
-- Name: siem_events siem_events_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.siem_events
    ADD CONSTRAINT siem_events_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: siem_incidents siem_incidents_assigned_to_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.siem_incidents
    ADD CONSTRAINT siem_incidents_assigned_to_fkey FOREIGN KEY (assigned_to) REFERENCES public.users(id);


--
-- Name: siem_incidents siem_incidents_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.siem_incidents
    ADD CONSTRAINT siem_incidents_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: siem_rules siem_rules_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.siem_rules
    ADD CONSTRAINT siem_rules_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: soc_twin_actions soc_twin_actions_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.soc_twin_actions
    ADD CONSTRAINT soc_twin_actions_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.soc_twin_sessions(id);


--
-- Name: te_events te_events_cluster_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.te_events
    ADD CONSTRAINT te_events_cluster_id_fkey FOREIGN KEY (cluster_id) REFERENCES public.te_clusters(id);


--
-- Name: terminal_audit_log terminal_audit_log_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.terminal_audit_log
    ADD CONSTRAINT terminal_audit_log_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: terminal_sessions terminal_sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.terminal_sessions
    ADD CONSTRAINT terminal_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: threat_intel_iocs threat_intel_iocs_feed_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_intel_iocs
    ADD CONSTRAINT threat_intel_iocs_feed_id_fkey FOREIGN KEY (feed_id) REFERENCES public.threat_intel_feeds(id);


--
-- Name: threat_matches threat_matches_ioc_entry_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_matches
    ADD CONSTRAINT threat_matches_ioc_entry_id_fkey FOREIGN KEY (ioc_entry_id) REFERENCES public.ioc_entries(id);


--
-- Name: threat_matches threat_matches_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_matches
    ADD CONSTRAINT threat_matches_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id);


--
-- Name: threat_matches threat_matches_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_matches
    ADD CONSTRAINT threat_matches_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: threat_radar_threats threat_radar_threats_report_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_radar_threats
    ADD CONSTRAINT threat_radar_threats_report_id_fkey FOREIGN KEY (report_id) REFERENCES public.threat_radar_reports(id);


--
-- Name: timeline_events timeline_events_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.timeline_events
    ADD CONSTRAINT timeline_events_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: twin_edges twin_edges_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.twin_edges
    ADD CONSTRAINT twin_edges_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.twin_nodes(id);


--
-- Name: twin_edges twin_edges_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.twin_edges
    ADD CONSTRAINT twin_edges_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.twin_nodes(id);


--
-- Name: twin_snapshots twin_snapshots_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.twin_snapshots
    ADD CONSTRAINT twin_snapshots_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: user_roles user_roles_assigned_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_assigned_by_fkey FOREIGN KEY (assigned_by) REFERENCES public.users(id);


--
-- Name: user_roles user_roles_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id);


--
-- Name: user_roles user_roles_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: user_settings user_settings_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_settings
    ADD CONSTRAINT user_settings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: watch_alerts watch_alerts_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.watch_alerts
    ADD CONSTRAINT watch_alerts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: watch_baselines watch_baselines_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.watch_baselines
    ADD CONSTRAINT watch_baselines_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: zt_access_log zt_access_log_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.zt_access_log
    ADD CONSTRAINT zt_access_log_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.zt_policies(id);


--
-- Name: zt_device_trust zt_device_trust_last_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.zt_device_trust
    ADD CONSTRAINT zt_device_trust_last_scan_id_fkey FOREIGN KEY (last_scan_id) REFERENCES public.scans(id);


--
-- Name: zt_policies zt_policies_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.zt_policies
    ADD CONSTRAINT zt_policies_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- PostgreSQL database dump complete
--

\unrestrict hVxxbJ88431bMvbN34eObOQIRYAweWOrUaYP5j1xGyUw7nfhcRy87uCrgrTPKWB

