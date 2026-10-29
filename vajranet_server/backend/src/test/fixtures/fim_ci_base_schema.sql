-- Minimal fleet base schema for the FIM DB test suites in CI (schema only, no data).
-- The fleet server owns these tables in production; this fixture mirrors only what the FIM
-- suites touch: nodes, config_queries, query_queue, query_result, alerts, dead_letter_queue,
-- win_registry_events. FIM tables come from migrations/030-032 applied on top.
-- Regenerate: pg_dump --schema-only --no-owner --no-privileges -t <tables> <throwaway db>
--
-- PostgreSQL database dump
--


-- Dumped from database version 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: alerts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alerts (
    id bigint NOT NULL,
    host_identifier character varying(40),
    hostname text,
    unixtime bigint,
    event_code text,
    metadata text,
    is_alert boolean,
    is_open boolean,
    remarks text,
    context_data text,
    severity text,
    alert_type text,
    technique text,
    technique_id text,
    link text,
    pid bigint,
    event_id bigint,
    action character varying(5),
    os_name text,
    detection_time bigint,
    original_hostname text,
    assign text,
    assignee_id integer,
    mark_type text,
    group_id character varying(255)
);


--
-- Name: alerts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.alerts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: alerts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.alerts_id_seq OWNED BY public.alerts.id;


--
-- Name: config_queries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.config_queries (
    id bigint NOT NULL,
    query text,
    query_name text,
    os_name text,
    kernel_version text,
    os_arch text
);


--
-- Name: config_queries_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.config_queries_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: config_queries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.config_queries_id_seq OWNED BY public.config_queries.id;


--
-- Name: dead_letter_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dead_letter_queue (
    id integer NOT NULL,
    event_id bigint,
    table_name text,
    error_message text,
    event_data text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: dead_letter_queue_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dead_letter_queue_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dead_letter_queue_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dead_letter_queue_id_seq OWNED BY public.dead_letter_queue.id;


--
-- Name: nodes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.nodes (
    id bigint NOT NULL,
    config_id text,
    host_identifier character varying(40) NOT NULL,
    os_arch text,
    os_build text,
    os_major text,
    os_minor text,
    os_name text,
    os_platform text,
    codename text,
    osquery_version text,
    node_key character varying(128),
    node_invalid boolean,
    reenroll_allowed boolean,
    hardware_vendor text,
    hardware_model text,
    hardware_version text,
    hostname text,
    enrolled_on bigint,
    last_seen bigint,
    hardware_cpu_logical_core text,
    hardware_cpu_type text,
    hardware_physical_memory text,
    isolated boolean,
    kernel_version text,
    original_hostname text,
    agent_online boolean,
    status character varying(20) DEFAULT 'ACTIVE'::character varying,
    consecutive_failures integer DEFAULT 0,
    node_key_expires_at bigint,
    device_group character varying(255) DEFAULT 'default'::character varying,
    address text,
    owner_group_id text
);


--
-- Name: nodes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.nodes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: nodes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.nodes_id_seq OWNED BY public.nodes.id;


--
-- Name: query_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.query_queue (
    id bigint NOT NULL,
    host_identifier character varying(40),
    query text,
    sent boolean,
    send_time bigint
);


--
-- Name: query_queue_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.query_queue_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: query_queue_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.query_queue_id_seq OWNED BY public.query_queue.id;


--
-- Name: query_result; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.query_result (
    id bigint NOT NULL,
    host_identifier character varying(40),
    unixtime bigint,
    query_name text,
    result text
);


--
-- Name: query_result_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.query_result_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: query_result_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.query_result_id_seq OWNED BY public.query_result.id;


--
-- Name: win_registry_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.win_registry_events (
    id bigint NOT NULL,
    host_identifier character varying(40),
    hostname text,
    unixtime bigint,
    action text,
    eid text,
    pid bigint,
    process_guid text,
    process_name text,
    target_name text,
    target_new_name text,
    value_type text,
    value_data text,
    owner_uid text,
    "time" bigint,
    utc_time text,
    eventid integer,
    is_processed boolean
);


--
-- Name: win_registry_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.win_registry_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: win_registry_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.win_registry_events_id_seq OWNED BY public.win_registry_events.id;


--
-- Name: alerts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alerts ALTER COLUMN id SET DEFAULT nextval('public.alerts_id_seq'::regclass);


--
-- Name: config_queries id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.config_queries ALTER COLUMN id SET DEFAULT nextval('public.config_queries_id_seq'::regclass);


--
-- Name: dead_letter_queue id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dead_letter_queue ALTER COLUMN id SET DEFAULT nextval('public.dead_letter_queue_id_seq'::regclass);


--
-- Name: nodes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nodes ALTER COLUMN id SET DEFAULT nextval('public.nodes_id_seq'::regclass);


--
-- Name: query_queue id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.query_queue ALTER COLUMN id SET DEFAULT nextval('public.query_queue_id_seq'::regclass);


--
-- Name: query_result id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.query_result ALTER COLUMN id SET DEFAULT nextval('public.query_result_id_seq'::regclass);


--
-- Name: win_registry_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.win_registry_events ALTER COLUMN id SET DEFAULT nextval('public.win_registry_events_id_seq'::regclass);


--
-- Name: alerts alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_pkey PRIMARY KEY (id);


--
-- Name: config_queries config_queries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.config_queries
    ADD CONSTRAINT config_queries_pkey PRIMARY KEY (id);


--
-- Name: dead_letter_queue dead_letter_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dead_letter_queue
    ADD CONSTRAINT dead_letter_queue_pkey PRIMARY KEY (id);


--
-- Name: nodes nodes_node_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nodes
    ADD CONSTRAINT nodes_node_key_key UNIQUE (node_key);


--
-- Name: nodes nodes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nodes
    ADD CONSTRAINT nodes_pkey PRIMARY KEY (host_identifier);


--
-- Name: query_queue query_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.query_queue
    ADD CONSTRAINT query_queue_pkey PRIMARY KEY (id);


--
-- Name: query_result query_result_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.query_result
    ADD CONSTRAINT query_result_pkey PRIMARY KEY (id);


--
-- Name: win_registry_events win_registry_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.win_registry_events
    ADD CONSTRAINT win_registry_events_pkey PRIMARY KEY (id);


--
-- PostgreSQL database dump complete
--


