--
-- PostgreSQL database dump
--

\restrict DDKyjeyoeDFn1SNDkLiWo8hGhs3drWoTO9mGJ8kHPnWJ7fDfZcmwoMSfqcXD6U9

-- Dumped from database version 18.1
-- Dumped by pg_dump version 18.1

-- Started on 2026-01-04 10:48:43

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

--
-- TOC entry 3 (class 3079 OID 24663)
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- TOC entry 5297 (class 0 OID 0)
-- Dependencies: 3
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- TOC entry 2 (class 3079 OID 16388)
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- TOC entry 5298 (class 0 OID 0)
-- Dependencies: 2
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


--
-- TOC entry 289 (class 1255 OID 24739)
-- Name: ai_stock_alerts_set_date(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.ai_stock_alerts_set_date() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.computed_date := NEW.computed_at::DATE;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.ai_stock_alerts_set_date() OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- TOC entry 233 (class 1259 OID 24785)
-- Name: ai_model_accuracy_daily; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.ai_model_accuracy_daily (
    row_id uuid DEFAULT gen_random_uuid() NOT NULL,
    day date NOT NULL,
    task text NOT NULL,
    crop text,
    model_version text NOT NULL,
    n integer NOT NULL,
    mae double precision NOT NULL,
    rmse double precision NOT NULL,
    mape double precision NOT NULL,
    computed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_model_accuracy_daily_mae_check CHECK ((mae >= (0)::double precision)),
    CONSTRAINT ai_model_accuracy_daily_mape_check CHECK ((mape >= (0)::double precision)),
    CONSTRAINT ai_model_accuracy_daily_n_check CHECK ((n >= 0)),
    CONSTRAINT ai_model_accuracy_daily_rmse_check CHECK ((rmse >= (0)::double precision)),
    CONSTRAINT ai_model_accuracy_daily_task_check CHECK ((task = ANY (ARRAY['price'::text, 'demand'::text, 'forecast'::text])))
);


ALTER TABLE public.ai_model_accuracy_daily OWNER TO postgres;

--
-- TOC entry 231 (class 1259 OID 24745)
-- Name: ai_model_evaluations; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.ai_model_evaluations (
    eval_id uuid DEFAULT gen_random_uuid() NOT NULL,
    model_name text NOT NULL,
    model_version text NOT NULL,
    metric text NOT NULL,
    predicted_value double precision,
    actual_value double precision,
    error double precision,
    evaluated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.ai_model_evaluations OWNER TO postgres;

--
-- TOC entry 232 (class 1259 OID 24759)
-- Name: ai_prediction_logs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.ai_prediction_logs (
    log_id uuid DEFAULT gen_random_uuid() NOT NULL,
    task text NOT NULL,
    crop text NOT NULL,
    entity_id uuid,
    model_version text NOT NULL,
    predicted_value double precision NOT NULL,
    actual_value double precision,
    predicted_at timestamp with time zone DEFAULT now() NOT NULL,
    actual_at timestamp with time zone,
    meta jsonb,
    CONSTRAINT ai_prediction_logs_actual_value_check CHECK ((actual_value >= (0)::double precision)),
    CONSTRAINT ai_prediction_logs_predicted_value_check CHECK ((predicted_value >= (0)::double precision)),
    CONSTRAINT ai_prediction_logs_task_check CHECK ((task = ANY (ARRAY['price'::text, 'demand'::text, 'forecast'::text])))
);


ALTER TABLE public.ai_prediction_logs OWNER TO postgres;

--
-- TOC entry 228 (class 1259 OID 16564)
-- Name: ai_rankings; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.ai_rankings (
    ranking_id uuid DEFAULT gen_random_uuid() NOT NULL,
    kind text NOT NULL,
    entity_id uuid NOT NULL,
    score double precision NOT NULL,
    window_days integer NOT NULL,
    model_version text NOT NULL,
    computed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_rankings_kind_check CHECK ((kind = ANY (ARRAY['product'::text, 'farmer'::text])))
);


ALTER TABLE public.ai_rankings OWNER TO postgres;

--
-- TOC entry 227 (class 1259 OID 16548)
-- Name: ai_request_log; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.ai_request_log (
    request_id uuid DEFAULT gen_random_uuid() NOT NULL,
    endpoint text NOT NULL,
    input_json jsonb NOT NULL,
    output_json jsonb,
    model_version text NOT NULL,
    cached boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.ai_request_log OWNER TO postgres;

--
-- TOC entry 230 (class 1259 OID 24701)
-- Name: ai_stock_alerts; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.ai_stock_alerts (
    alert_id uuid DEFAULT gen_random_uuid() NOT NULL,
    farmer_id uuid NOT NULL,
    product_id uuid NOT NULL,
    predicted_demand double precision NOT NULL,
    available_stock double precision NOT NULL,
    recommended_restock double precision NOT NULL,
    severity text NOT NULL,
    model_version text NOT NULL,
    computed_at timestamp with time zone DEFAULT now() NOT NULL,
    computed_date date,
    acknowledged boolean DEFAULT false NOT NULL,
    acknowledged_at timestamp with time zone,
    resolved boolean DEFAULT false NOT NULL,
    resolved_at timestamp with time zone,
    CONSTRAINT ai_stock_alerts_available_stock_check CHECK ((available_stock >= (0)::double precision)),
    CONSTRAINT ai_stock_alerts_predicted_demand_check CHECK ((predicted_demand >= (0)::double precision)),
    CONSTRAINT ai_stock_alerts_recommended_restock_check CHECK ((recommended_restock >= (0)::double precision)),
    CONSTRAINT ai_stock_alerts_severity_check CHECK ((severity = ANY (ARRAY['low'::text, 'medium'::text, 'high'::text])))
);


ALTER TABLE public.ai_stock_alerts OWNER TO postgres;

--
-- TOC entry 234 (class 1259 OID 24812)
-- Name: cart_items; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.cart_items (
    cart_item_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id uuid NOT NULL,
    product_id uuid NOT NULL,
    qty numeric(12,3) NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT cart_items_qty_check CHECK ((qty > (0)::numeric)),
    CONSTRAINT cart_items_qty_positive CHECK ((qty > (0)::numeric))
);


ALTER TABLE public.cart_items OWNER TO postgres;

--
-- TOC entry 238 (class 1259 OID 24971)
-- Name: order_items; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.order_items (
    order_item_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    order_id uuid NOT NULL,
    product_id uuid NOT NULL,
    quantity numeric(12,3) NOT NULL,
    unit_price numeric(10,2) NOT NULL,
    line_total numeric(12,2) NOT NULL,
    unit character varying(20) NOT NULL,
    pack_size numeric(12,3),
    pack_unit character varying(20),
    created_at timestamp without time zone DEFAULT now(),
    CONSTRAINT chk_price_positive CHECK ((unit_price >= (0)::numeric)),
    CONSTRAINT chk_quantity_positive CHECK ((quantity > (0)::numeric))
);


ALTER TABLE public.order_items OWNER TO postgres;

--
-- TOC entry 223 (class 1259 OID 16444)
-- Name: orders; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.orders (
    order_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    buyer_id uuid NOT NULL,
    order_date timestamp without time zone DEFAULT now() NOT NULL,
    status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    payment_status character varying(20) DEFAULT 'unpaid'::character varying NOT NULL,
    paid_at timestamp without time zone,
    payment_reference character varying(120),
    order_total numeric(10,2) DEFAULT 0,
    CONSTRAINT chk_valid_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'completed'::character varying, 'cancelled'::character varying])::text[])))
);


ALTER TABLE public.orders OWNER TO postgres;

--
-- TOC entry 222 (class 1259 OID 16423)
-- Name: products; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.products (
    product_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id uuid NOT NULL,
    product_name character varying(200) NOT NULL,
    description text,
    price numeric(10,2) NOT NULL,
    quantity numeric(12,3) DEFAULT 0 NOT NULL,
    image_url text,
    category character varying(100),
    status character varying(50) DEFAULT 'available'::character varying,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    unit character varying(20) DEFAULT 'each'::character varying NOT NULL,
    pack_size numeric(12,3),
    pack_unit character varying(20),
    CONSTRAINT products_pack_check CHECK ((((unit)::text <> 'pack'::text) OR (((unit)::text = 'pack'::text) AND (pack_size IS NOT NULL) AND (pack_unit IS NOT NULL)))),
    CONSTRAINT products_unit_check CHECK (((unit)::text = ANY ((ARRAY['kg'::character varying, 'g'::character varying, 'l'::character varying, 'ml'::character varying, 'each'::character varying, 'pack'::character varying])::text[])))
);


ALTER TABLE public.products OWNER TO postgres;

--
-- TOC entry 221 (class 1259 OID 16399)
-- Name: users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    full_name character varying(200) NOT NULL,
    phone character varying(20) NOT NULL,
    email character varying(200) NOT NULL,
    location character varying(150),
    password_hash character varying(255) NOT NULL,
    role integer NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    deleted_at timestamp without time zone
);


ALTER TABLE public.users OWNER TO postgres;

--
-- TOC entry 240 (class 1259 OID 25001)
-- Name: v_customer_repeat_purchases; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_customer_repeat_purchases AS
 SELECT o.buyer_id,
    oi.product_id,
    count(DISTINCT o.order_id) AS purchase_count
   FROM (public.orders o
     JOIN public.order_items oi ON ((oi.order_id = o.order_id)))
  GROUP BY o.buyer_id, oi.product_id
 HAVING (count(DISTINCT o.order_id) > 1);


ALTER VIEW public.v_customer_repeat_purchases OWNER TO postgres;

--
-- TOC entry 241 (class 1259 OID 25006)
-- Name: customer_repeat_purchases; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.customer_repeat_purchases AS
 SELECT u.id AS customer_id,
    u.full_name AS customer_name,
    p.product_name,
    rp.purchase_count
   FROM ((public.v_customer_repeat_purchases rp
     JOIN public.users u ON ((u.id = rp.buyer_id)))
     JOIN public.products p ON ((p.product_id = rp.product_id)));


ALTER VIEW public.customer_repeat_purchases OWNER TO postgres;

--
-- TOC entry 229 (class 1259 OID 16581)
-- Name: customer_search_events; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.customer_search_events (
    event_id uuid DEFAULT gen_random_uuid() NOT NULL,
    customer_id uuid NOT NULL,
    query text NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.customer_search_events OWNER TO postgres;

--
-- TOC entry 224 (class 1259 OID 16467)
-- Name: market_trends; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.market_trends (
    trend_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    product_id uuid NOT NULL,
    demand_index integer NOT NULL,
    avg_price numeric(10,2) NOT NULL,
    "timestamp" timestamp without time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.market_trends OWNER TO postgres;

--
-- TOC entry 237 (class 1259 OID 24916)
-- Name: payments; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.payments (
    payment_id integer NOT NULL,
    order_id uuid NOT NULL,
    amount numeric(10,2) NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    method character varying(30),
    reference character varying(120),
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.payments OWNER TO postgres;

--
-- TOC entry 236 (class 1259 OID 24915)
-- Name: payments_payment_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.payments_payment_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.payments_payment_id_seq OWNER TO postgres;

--
-- TOC entry 5299 (class 0 OID 0)
-- Dependencies: 236
-- Name: payments_payment_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.payments_payment_id_seq OWNED BY public.payments.payment_id;


--
-- TOC entry 226 (class 1259 OID 16504)
-- Name: ratings; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.ratings (
    rating_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    product_id uuid NOT NULL,
    user_id uuid NOT NULL,
    rating_score integer NOT NULL,
    comments text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    order_id uuid,
    CONSTRAINT ratings_rating_score_check CHECK (((rating_score >= 1) AND (rating_score <= 5)))
);


ALTER TABLE public.ratings OWNER TO postgres;

--
-- TOC entry 225 (class 1259 OID 16484)
-- Name: sms_logs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.sms_logs (
    sms_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id uuid NOT NULL,
    message_content text NOT NULL,
    "timestamp" timestamp without time zone DEFAULT now() NOT NULL,
    status character varying(50) DEFAULT 'sent'::character varying NOT NULL,
    template_name character varying(100),
    context jsonb,
    provider character varying(50) DEFAULT 'console'::character varying,
    attempt_count integer DEFAULT 0,
    last_error text,
    queued_at timestamp with time zone,
    sent_at timestamp with time zone,
    delivered_at timestamp with time zone
);


ALTER TABLE public.sms_logs OWNER TO postgres;

--
-- TOC entry 235 (class 1259 OID 24838)
-- Name: top_searched_products; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.top_searched_products AS
 SELECT query,
    count(*) AS searches
   FROM public.customer_search_events
  GROUP BY query
  ORDER BY (count(*)) DESC;


ALTER VIEW public.top_searched_products OWNER TO postgres;

--
-- TOC entry 239 (class 1259 OID 24996)
-- Name: v_revenue_by_product; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.v_revenue_by_product AS
 SELECT p.product_id,
    p.product_name,
    p.unit,
    sum(oi.quantity) AS total_quantity_sold,
    sum(oi.line_total) AS total_revenue
   FROM ((public.order_items oi
     JOIN public.products p ON ((p.product_id = oi.product_id)))
     JOIN public.orders o ON ((o.order_id = oi.order_id)))
  WHERE ((o.status)::text = 'completed'::text)
  GROUP BY p.product_id, p.product_name, p.unit;


ALTER VIEW public.v_revenue_by_product OWNER TO postgres;

--
-- TOC entry 5024 (class 2604 OID 24919)
-- Name: payments payment_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.payments ALTER COLUMN payment_id SET DEFAULT nextval('public.payments_payment_id_seq'::regclass);


--
-- TOC entry 5287 (class 0 OID 24785)
-- Dependencies: 233
-- Data for Name: ai_model_accuracy_daily; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.ai_model_accuracy_daily (row_id, day, task, crop, model_version, n, mae, rmse, mape, computed_at) FROM stdin;
\.


--
-- TOC entry 5285 (class 0 OID 24745)
-- Dependencies: 231
-- Data for Name: ai_model_evaluations; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.ai_model_evaluations (eval_id, model_name, model_version, metric, predicted_value, actual_value, error, evaluated_at) FROM stdin;
\.


--
-- TOC entry 5286 (class 0 OID 24759)
-- Dependencies: 232
-- Data for Name: ai_prediction_logs; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.ai_prediction_logs (log_id, task, crop, entity_id, model_version, predicted_value, actual_value, predicted_at, actual_at, meta) FROM stdin;
\.


--
-- TOC entry 5282 (class 0 OID 16564)
-- Dependencies: 228
-- Data for Name: ai_rankings; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.ai_rankings (ranking_id, kind, entity_id, score, window_days, model_version, computed_at) FROM stdin;
\.


--
-- TOC entry 5281 (class 0 OID 16548)
-- Dependencies: 227
-- Data for Name: ai_request_log; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.ai_request_log (request_id, endpoint, input_json, output_json, model_version, cached, created_at) FROM stdin;
\.


--
-- TOC entry 5284 (class 0 OID 24701)
-- Dependencies: 230
-- Data for Name: ai_stock_alerts; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.ai_stock_alerts (alert_id, farmer_id, product_id, predicted_demand, available_stock, recommended_restock, severity, model_version, computed_at, computed_date, acknowledged, acknowledged_at, resolved, resolved_at) FROM stdin;
\.


--
-- TOC entry 5288 (class 0 OID 24812)
-- Dependencies: 234
-- Data for Name: cart_items; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.cart_items (cart_item_id, user_id, product_id, qty, created_at) FROM stdin;
\.


--
-- TOC entry 5283 (class 0 OID 16581)
-- Dependencies: 229
-- Data for Name: customer_search_events; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.customer_search_events (event_id, customer_id, query, occurred_at) FROM stdin;
\.


--
-- TOC entry 5278 (class 0 OID 16467)
-- Dependencies: 224
-- Data for Name: market_trends; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.market_trends (trend_id, product_id, demand_index, avg_price, "timestamp") FROM stdin;
37c0de96-6836-41d7-843e-c4d29eca8dbb	099d03d8-79c1-4426-8052-0e65e9a70521	85	118.00	2025-11-13 00:00:00
5bc5e08a-d761-4fbc-8b36-9617d959c3da	fb816ea6-30fc-415a-9d03-eab94ada9f9f	72	14.50	2025-11-13 00:00:00
d5c05c86-9638-438b-bfac-a4812b027b16	22b1384e-41f8-4be6-b9b1-257d7327499b	60	98.00	2025-11-13 00:00:00
\.


--
-- TOC entry 5291 (class 0 OID 24971)
-- Dependencies: 238
-- Data for Name: order_items; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.order_items (order_item_id, order_id, product_id, quantity, unit_price, line_total, unit, pack_size, pack_unit, created_at) FROM stdin;
5fc7b528-5f29-40da-b96e-4c5acfa76f98	e6c45d08-43f9-4dd4-887b-52ca5deb4c0e	099d03d8-79c1-4426-8052-0e65e9a70521	1.000	120.00	125.00	each	\N	\N	2026-01-03 22:15:23.369048
bad6e97f-3b66-4999-a752-ff07c54efc8d	0e14dfbc-a6aa-449c-8b37-528b463f6894	22b1384e-41f8-4be6-b9b1-257d7327499b	1.000	100.00	105.00	each	\N	\N	2026-01-03 22:15:23.369048
b5c3d348-dd4d-461d-bb3b-e5be8e364dd3	b6455266-a62c-484d-9a5b-9c4222111daf	fb816ea6-30fc-415a-9d03-eab94ada9f9f	1.000	15.00	20.00	each	\N	\N	2026-01-03 22:15:23.369048
\.


--
-- TOC entry 5277 (class 0 OID 16444)
-- Dependencies: 223
-- Data for Name: orders; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.orders (order_id, buyer_id, order_date, status, payment_status, paid_at, payment_reference, order_total) FROM stdin;
e6c45d08-43f9-4dd4-887b-52ca5deb4c0e	8089381d-495b-4202-a82a-1d2ca54a9185	2025-11-13 00:00:00	completed	unpaid	\N	\N	125.00
0e14dfbc-a6aa-449c-8b37-528b463f6894	3ff20f76-d9e8-42c6-817e-5d3e13c0048d	2025-11-12 00:00:00	completed	unpaid	\N	\N	105.00
b6455266-a62c-484d-9a5b-9c4222111daf	b9195d1e-d31e-4651-ba72-ae7ac86dee69	2025-11-14 00:00:00	pending	unpaid	\N	\N	20.00
\.


--
-- TOC entry 5290 (class 0 OID 24916)
-- Dependencies: 237
-- Data for Name: payments; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.payments (payment_id, order_id, amount, status, method, reference, created_at) FROM stdin;
\.


--
-- TOC entry 5276 (class 0 OID 16423)
-- Dependencies: 222
-- Data for Name: products; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.products (product_id, user_id, product_name, description, price, quantity, image_url, category, status, created_at, unit, pack_size, pack_unit) FROM stdin;
099d03d8-79c1-4426-8052-0e65e9a70521	8c325faa-e2f1-4c92-b48b-720f7199d8bb	Mahangu (Pearl Millet)	Drought-resistant staple grain, harvested fresh from Etunda fields.	120.00	80.000	default/millet.jpg	grain	available	2025-11-12 14:37:27	each	\N	\N
0ffd7ac8-0ccc-41d0-ae17-147c21e4cd99	8c325faa-e2f1-4c92-b48b-720f7199d8bb	Maize	Yellow maize cobs, ideal for porridge or mealie meal.	180.00	50.000	default/maize.jpg	grain	available	2025-11-12 14:37:27	each	\N	\N
15b5c76f-4536-401f-b059-12b1752118f3	8c325faa-e2f1-4c92-b48b-720f7199d8bb	Carrots	Fresh orange root carrots, grown with groundwater irrigation.	15.00	40.000	default/carrot.jpg	root	available	2025-11-12 14:37:27	each	\N	\N
9e741ad5-3f6c-4fbd-962b-43404a325a74	8c325faa-e2f1-4c92-b48b-720f7199d8bb	Potatoes	Red-skinned potatoes, suitable for boiling or chips.	25.00	30.000	default/potato.jpg	root	available	2025-11-12 14:37:27	each	\N	\N
22b1384e-41f8-4be6-b9b1-257d7327499b	05fa5925-c325-4e88-9143-5d522a9ccee6	Cowpeas (Beans)	Protein-rich black-eyed beans, traditional Rundu variety.	100.00	60.000	default/beans.jpg	legume	available	2025-11-12 14:37:27	each	\N	\N
f7118be9-de5e-483e-953f-68310f1b9879	05fa5925-c325-4e88-9143-5d522a9ccee6	Sorghum	White sorghum grain for baking or brewing.	140.00	70.000	default/sorghum.jpg	grain	available	2025-11-12 14:37:27	each	\N	\N
6f5f1988-6f9d-4d7a-a271-5a9b83cded9c	05fa5925-c325-4e88-9143-5d522a9ccee6	Onions	Red onions, Namibia's top vegetable crop – crisp and storage-friendly.	10.00	120.000	default/onion.jpg	vegetable	available	2025-11-12 14:37:27	each	\N	\N
fb816ea6-30fc-415a-9d03-eab94ada9f9f	33ddf062-6e25-4d39-9582-d23c6de9f19b	Tomatoes	Ripe red tomatoes from Caprivi floodplains.	15.00	100.000	default/tomato.jpg	vegetable	available	2025-11-12 14:37:27	each	\N	\N
3df3eb15-4231-430e-98f3-fb06176f19ab	33ddf062-6e25-4d39-9582-d23c6de9f19b	Cabbage	Green cabbages, perfect for salads or stews.	20.00	50.000	default/cabbage.jpg	vegetable	available	2025-11-12 14:37:27	each	\N	\N
ac16c6ca-4da1-41b8-a761-4439959b73c3	33ddf062-6e25-4d39-9582-d23c6de9f19b	Peas	Green peas in pods, fresh-picked for market.	18.00	25.000	default/peas.jpg	legume	available	2025-11-12 14:37:27	each	\N	\N
508ef5c4-8327-419d-b997-e271cbe1b807	04e49484-c554-491e-8b5c-9e2633af694a	Onions	White onions from Rehoboth irrigation schemes.	12.00	150.000	default/onion.jpg	vegetable	available	2025-11-12 14:37:27	each	\N	\N
e43a9a60-bf62-4987-9242-55fb3c2bccd3	04e49484-c554-491e-8b5c-9e2633af694a	Wheat	Durum wheat for bread-making, limited yield due to aridity.	200.00	40.000	default/wheat.jpg	grain	available	2025-11-12 14:37:27	each	\N	\N
8eaba99b-df38-4064-aa36-dee7aa6d1623	04e49484-c554-491e-8b5c-9e2633af694a	Cabbage	White cabbages, hardy in southern climates.	22.00	45.000	default/cabbage.jpg	vegetable	available	2025-11-12 14:37:27	each	\N	\N
0ee27e1a-7114-431d-bf7c-43fcf73e52f7	04e49484-c554-491e-8b5c-9e2633af694a	Lucerne (Alfalfa)	Green lucerne hay for livestock feed.	80.00	90.000	default/lucerne.jpg	legume	available	2025-11-12 14:37:27	each	\N	\N
\.


--
-- TOC entry 5280 (class 0 OID 16504)
-- Dependencies: 226
-- Data for Name: ratings; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.ratings (rating_id, product_id, user_id, rating_score, comments, created_at, order_id) FROM stdin;
f09b5137-0790-497a-ba4b-a07ba2b274e6	fb816ea6-30fc-415a-9d03-eab94ada9f9f	b9195d1e-d31e-4651-ba72-ae7ac86dee69	5	Fresh and juicy tomatoes, very good quality!	2025-11-13 00:00:00	\N
f75ce644-bcd7-41b0-898c-45cbd7fd9e66	22b1384e-41f8-4be6-b9b1-257d7327499b	3ff20f76-d9e8-42c6-817e-5d3e13c0048d	4	Good beans but packaging could improve.	2025-11-12 00:00:00	\N
004323bb-8103-42fb-abbd-e51f37dce25d	099d03d8-79c1-4426-8052-0e65e9a70521	8089381d-495b-4202-a82a-1d2ca54a9185	5	Mahangu was high quality and clean. Excellent!	2025-11-14 00:00:00	\N
\.


--
-- TOC entry 5279 (class 0 OID 16484)
-- Dependencies: 225
-- Data for Name: sms_logs; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.sms_logs (sms_id, user_id, message_content, "timestamp", status, template_name, context, provider, attempt_count, last_error, queued_at, sent_at, delivered_at) FROM stdin;
73540cad-ed54-4368-9e2f-4b2421206dfa	8c325faa-e2f1-4c92-b48b-720f7199d8bb	Your product Mahangu has been successfully added to AgroConnect.	2025-11-12 00:00:00	sent	\N	\N	console	0	\N	\N	\N	\N
e3f5e3a9-c58d-4db8-a314-9aad448d5c11	05fa5925-c325-4e88-9143-5d522a9ccee6	Order #103 confirmed. Please prepare goods for collection.	2025-11-13 00:00:00	delivered	\N	\N	console	0	\N	\N	\N	\N
3092d8a2-52c9-45db-aa63-5cd654e674e8	8089381d-495b-4202-a82a-1d2ca54a9185	Thank you for your order! Your request is being processed.	2025-11-13 00:00:00	sent	\N	\N	console	0	\N	\N	\N	\N
\.


--
-- TOC entry 5275 (class 0 OID 16399)
-- Dependencies: 221
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.users (id, full_name, phone, email, location, password_hash, role, created_at, updated_at, is_active, deleted_at) FROM stdin;
8c325faa-e2f1-4c92-b48b-720f7199d8bb	Mekondjo Nuuyoma	0810123456	mekondjo.nuuyoma@gmail.com	Etunda	$2b$12$mLbnLJCRjWMQgAP5Eo22Q.uJ2o/PUMjYWzTcGGYZ6VhN0Nm4KKAwK	2	2025-08-05 10:22:11	2025-09-28 14:44:01	t	\N
05fa5925-c325-4e88-9143-5d522a9ccee6	Maria Mungeli	0816543210	maria.mungeli@gmail.com	Rundu	$2b$12$do/GrWtqvLpDxxbs8mj1X.dmsSnQBDQusvb7o6YQG27A1DSTRnNlG	2	2025-08-12 09:15:43	2025-10-02 17:51:20	t	\N
33ddf062-6e25-4d39-9582-d23c6de9f19b	Mushaukwa Ntelamo	0814006000	conardntelamo11@gmail.com	Katima Mulilo	$2b$12$kHAr5uPh.MFIjNXNYTuYQ.eK0kyWVE1z/dMlvpTF384ESZ5t1v3by	2	2025-09-03 08:41:52	2025-10-05 15:33:19	t	\N
04e49484-c554-491e-8b5c-9e2633af694a	Anton Van Wyk	0812233455	anton.vanwyk@gmail.com	Rehoboth	$2b$12$D9f1P.Y4KRoKrV8yQDTfyOqq9.9sl2kixZ8iCHHi5Tpyv5ESTFBoe	2	2025-08-29 13:22:09	2025-09-30 16:27:44	t	\N
8089381d-495b-4202-a82a-1d2ca54a9185	Nzwana Situmbeko	0812000345	nzwana.situmbeko@gmail.com	Windhoek	$2b$12$KXepCTwhfE6RhS7qYx1v.ewJGNQhBBJBiy0jtTesX6JItiDkFG62m	3	2025-09-11 11:12:55	2025-10-06 18:22:51	t	\N
e03a47ff-c0ee-4ade-8078-7dbf0d2eac50	Mushabati Ntelamo	0815566789	mushabati.ntelamo@gmail.com	Ongwediva	$2b$12$0KZQN8B2syN/AI0MiaDoteGE5Jr6VYq8v/5MvKCfQV407qc9D8P9K	3	2025-08-07 07:19:08	2025-09-29 19:45:02	t	\N
3ff20f76-d9e8-42c6-817e-5d3e13c0048d	Catherine Situmbeko	0815566778	catherine.situmbeko@gmail.com	Windhoek	$2b$12$Oy/CMN1OKjIDV3mwRTM8UO4vP1ik4weupfjHJVImWPonAbcii/kuC	3	2025-09-15 10:55:49	2025-10-08 13:19:33	t	\N
b9195d1e-d31e-4651-ba72-ae7ac86dee69	Martha Armas	0812345678	marthaarmas@gmail.com	Oshakati	$2b$12$ycUyqGQht5ojkkyPICiYzuRZXduVVHeNR//1V26hTfWx1GShMW4yO	3	2025-09-07 14:19:31	2025-10-09 16:10:27	t	\N
a73834bd-addf-4fdc-b887-ee491f3b5db0	Conard Ntelamo	0814006117	tcntelamo@gmail.com	Katima Mulilo	$2b$12$ErHmdSS/tzmcTfa5pXlqE.6uLA4jxwwwRf525GfAJtyq8nKZw8M9i	1	2025-12-29 17:04:45.726645	2025-12-29 17:04:45.726652	t	\N
\.


--
-- TOC entry 5300 (class 0 OID 0)
-- Dependencies: 236
-- Name: payments_payment_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.payments_payment_id_seq', 1, false);


--
-- TOC entry 5086 (class 2606 OID 24809)
-- Name: ai_model_accuracy_daily ai_model_accuracy_daily_day_task_crop_model_version_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ai_model_accuracy_daily
    ADD CONSTRAINT ai_model_accuracy_daily_day_task_crop_model_version_key UNIQUE (day, task, crop, model_version);


--
-- TOC entry 5088 (class 2606 OID 24807)
-- Name: ai_model_accuracy_daily ai_model_accuracy_daily_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ai_model_accuracy_daily
    ADD CONSTRAINT ai_model_accuracy_daily_pkey PRIMARY KEY (row_id);


--
-- TOC entry 5079 (class 2606 OID 24758)
-- Name: ai_model_evaluations ai_model_evaluations_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ai_model_evaluations
    ADD CONSTRAINT ai_model_evaluations_pkey PRIMARY KEY (eval_id);


--
-- TOC entry 5081 (class 2606 OID 24776)
-- Name: ai_prediction_logs ai_prediction_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ai_prediction_logs
    ADD CONSTRAINT ai_prediction_logs_pkey PRIMARY KEY (log_id);


--
-- TOC entry 5070 (class 2606 OID 16580)
-- Name: ai_rankings ai_rankings_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ai_rankings
    ADD CONSTRAINT ai_rankings_pkey PRIMARY KEY (ranking_id);


--
-- TOC entry 5068 (class 2606 OID 16563)
-- Name: ai_request_log ai_request_log_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ai_request_log
    ADD CONSTRAINT ai_request_log_pkey PRIMARY KEY (request_id);


--
-- TOC entry 5075 (class 2606 OID 24722)
-- Name: ai_stock_alerts ai_stock_alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ai_stock_alerts
    ADD CONSTRAINT ai_stock_alerts_pkey PRIMARY KEY (alert_id);


--
-- TOC entry 5092 (class 2606 OID 24821)
-- Name: cart_items cart_items_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.cart_items
    ADD CONSTRAINT cart_items_pkey PRIMARY KEY (cart_item_id);


--
-- TOC entry 5094 (class 2606 OID 24823)
-- Name: cart_items cart_items_user_id_product_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.cart_items
    ADD CONSTRAINT cart_items_user_id_product_id_key UNIQUE (user_id, product_id);


--
-- TOC entry 5072 (class 2606 OID 16593)
-- Name: customer_search_events customer_search_events_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.customer_search_events
    ADD CONSTRAINT customer_search_events_pkey PRIMARY KEY (event_id);


--
-- TOC entry 5062 (class 2606 OID 16478)
-- Name: market_trends market_trends_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.market_trends
    ADD CONSTRAINT market_trends_pkey PRIMARY KEY (trend_id);


--
-- TOC entry 5105 (class 2606 OID 24984)
-- Name: order_items order_items_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.order_items
    ADD CONSTRAINT order_items_pkey PRIMARY KEY (order_item_id);


--
-- TOC entry 5060 (class 2606 OID 16456)
-- Name: orders orders_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_pkey PRIMARY KEY (order_id);


--
-- TOC entry 5101 (class 2606 OID 24928)
-- Name: payments payments_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_pkey PRIMARY KEY (payment_id);


--
-- TOC entry 5057 (class 2606 OID 16438)
-- Name: products products_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.products
    ADD CONSTRAINT products_pkey PRIMARY KEY (product_id);


--
-- TOC entry 5066 (class 2606 OID 16518)
-- Name: ratings ratings_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ratings
    ADD CONSTRAINT ratings_pkey PRIMARY KEY (rating_id);


--
-- TOC entry 5064 (class 2606 OID 16498)
-- Name: sms_logs sms_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.sms_logs
    ADD CONSTRAINT sms_logs_pkey PRIMARY KEY (sms_id);


--
-- TOC entry 5098 (class 2606 OID 25039)
-- Name: cart_items uq_cart_user_product; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.cart_items
    ADD CONSTRAINT uq_cart_user_product UNIQUE (user_id, product_id);


--
-- TOC entry 5051 (class 2606 OID 16422)
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- TOC entry 5053 (class 2606 OID 16420)
-- Name: users users_phone_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_phone_key UNIQUE (phone);


--
-- TOC entry 5055 (class 2606 OID 16418)
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- TOC entry 5089 (class 1259 OID 24810)
-- Name: idx_ai_acc_daily_day_task; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_ai_acc_daily_day_task ON public.ai_model_accuracy_daily USING btree (day DESC, task);


--
-- TOC entry 5090 (class 1259 OID 24811)
-- Name: idx_ai_acc_daily_model; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_ai_acc_daily_model ON public.ai_model_accuracy_daily USING btree (model_version, task, day DESC);


--
-- TOC entry 5082 (class 1259 OID 24784)
-- Name: idx_ai_pred_logs_crop_task_time; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_ai_pred_logs_crop_task_time ON public.ai_prediction_logs USING btree (crop, task, predicted_at DESC);


--
-- TOC entry 5083 (class 1259 OID 24783)
-- Name: idx_ai_pred_logs_model_task_time; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_ai_pred_logs_model_task_time ON public.ai_prediction_logs USING btree (model_version, task, predicted_at DESC);


--
-- TOC entry 5084 (class 1259 OID 24782)
-- Name: idx_ai_pred_logs_task_time; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_ai_pred_logs_task_time ON public.ai_prediction_logs USING btree (task, predicted_at DESC);


--
-- TOC entry 5076 (class 1259 OID 24733)
-- Name: idx_ai_stock_alerts_time; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_ai_stock_alerts_time ON public.ai_stock_alerts USING btree (computed_at DESC);


--
-- TOC entry 5058 (class 1259 OID 25021)
-- Name: idx_orders_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_orders_status ON public.orders USING btree (status);


--
-- TOC entry 5099 (class 1259 OID 24934)
-- Name: idx_payments_order_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_payments_order_id ON public.payments USING btree (order_id);


--
-- TOC entry 5095 (class 1259 OID 25041)
-- Name: ix_cart_items_product_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_cart_items_product_id ON public.cart_items USING btree (product_id);


--
-- TOC entry 5096 (class 1259 OID 25040)
-- Name: ix_cart_items_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_cart_items_user_id ON public.cart_items USING btree (user_id);


--
-- TOC entry 5102 (class 1259 OID 25042)
-- Name: ix_order_items_order_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_order_items_order_id ON public.order_items USING btree (order_id);


--
-- TOC entry 5103 (class 1259 OID 25043)
-- Name: ix_order_items_product_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_order_items_product_id ON public.order_items USING btree (product_id);


--
-- TOC entry 5073 (class 1259 OID 16599)
-- Name: ix_search_customer_time; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_search_customer_time ON public.customer_search_events USING btree (customer_id, occurred_at DESC);


--
-- TOC entry 5077 (class 1259 OID 24734)
-- Name: uq_ai_stock_alerts_daily; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX uq_ai_stock_alerts_daily ON public.ai_stock_alerts USING btree (product_id, date_trunc('day'::text, (computed_at AT TIME ZONE 'UTC'::text)));


--
-- TOC entry 5106 (class 1259 OID 24995)
-- Name: uq_order_items_one_product_per_order; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX uq_order_items_one_product_per_order ON public.order_items USING btree (order_id, product_id);


--
-- TOC entry 5123 (class 2620 OID 24740)
-- Name: ai_stock_alerts trg_ai_stock_alerts_set_date; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trg_ai_stock_alerts_set_date BEFORE INSERT OR UPDATE OF computed_at ON public.ai_stock_alerts FOR EACH ROW EXECUTE FUNCTION public.ai_stock_alerts_set_date();


--
-- TOC entry 5117 (class 2606 OID 24777)
-- Name: ai_prediction_logs ai_prediction_logs_entity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ai_prediction_logs
    ADD CONSTRAINT ai_prediction_logs_entity_id_fkey FOREIGN KEY (entity_id) REFERENCES public.products(product_id) ON DELETE SET NULL;


--
-- TOC entry 5115 (class 2606 OID 24723)
-- Name: ai_stock_alerts ai_stock_alerts_farmer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ai_stock_alerts
    ADD CONSTRAINT ai_stock_alerts_farmer_id_fkey FOREIGN KEY (farmer_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- TOC entry 5116 (class 2606 OID 24728)
-- Name: ai_stock_alerts ai_stock_alerts_product_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ai_stock_alerts
    ADD CONSTRAINT ai_stock_alerts_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(product_id) ON DELETE CASCADE;


--
-- TOC entry 5118 (class 2606 OID 24829)
-- Name: cart_items cart_items_product_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.cart_items
    ADD CONSTRAINT cart_items_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(product_id) ON DELETE CASCADE;


--
-- TOC entry 5119 (class 2606 OID 24824)
-- Name: cart_items cart_items_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.cart_items
    ADD CONSTRAINT cart_items_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- TOC entry 5114 (class 2606 OID 16594)
-- Name: customer_search_events customer_search_events_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.customer_search_events
    ADD CONSTRAINT customer_search_events_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.users(id);


--
-- TOC entry 5109 (class 2606 OID 16479)
-- Name: market_trends market_trends_product_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.market_trends
    ADD CONSTRAINT market_trends_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(product_id) ON DELETE CASCADE;


--
-- TOC entry 5121 (class 2606 OID 24985)
-- Name: order_items order_items_order_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.order_items
    ADD CONSTRAINT order_items_order_id_fkey FOREIGN KEY (order_id) REFERENCES public.orders(order_id) ON DELETE CASCADE;


--
-- TOC entry 5122 (class 2606 OID 24990)
-- Name: order_items order_items_product_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.order_items
    ADD CONSTRAINT order_items_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(product_id);


--
-- TOC entry 5108 (class 2606 OID 16462)
-- Name: orders orders_buyer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_buyer_id_fkey FOREIGN KEY (buyer_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- TOC entry 5120 (class 2606 OID 24929)
-- Name: payments payments_order_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_order_id_fkey FOREIGN KEY (order_id) REFERENCES public.orders(order_id) ON DELETE CASCADE;


--
-- TOC entry 5107 (class 2606 OID 16439)
-- Name: products products_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.products
    ADD CONSTRAINT products_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- TOC entry 5111 (class 2606 OID 24870)
-- Name: ratings ratings_order_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ratings
    ADD CONSTRAINT ratings_order_id_fkey FOREIGN KEY (order_id) REFERENCES public.orders(order_id) ON DELETE SET NULL;


--
-- TOC entry 5112 (class 2606 OID 16519)
-- Name: ratings ratings_product_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ratings
    ADD CONSTRAINT ratings_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(product_id) ON DELETE CASCADE;


--
-- TOC entry 5113 (class 2606 OID 16524)
-- Name: ratings ratings_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ratings
    ADD CONSTRAINT ratings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- TOC entry 5110 (class 2606 OID 16499)
-- Name: sms_logs sms_logs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.sms_logs
    ADD CONSTRAINT sms_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


-- Completed on 2026-01-04 10:48:43

--
-- PostgreSQL database dump complete
--

\unrestrict DDKyjeyoeDFn1SNDkLiWo8hGhs3drWoTO9mGJ8kHPnWJ7fDfZcmwoMSfqcXD6U9

