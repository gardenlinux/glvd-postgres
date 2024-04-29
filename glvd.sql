--
-- PostgreSQL database dump
--

-- Dumped from database version 15.6 (Debian 15.6-1.pgdg120+2)
-- Dumped by pg_dump version 16.2 (Debian 16.2-1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: debversion; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS debversion WITH SCHEMA public;


--
-- Name: EXTENSION debversion; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION debversion IS 'Debian version number data type';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: all_cve; Type: TABLE; Schema: public; Owner: glvd
--

CREATE TABLE public.all_cve (
    cve_id text NOT NULL,
    last_mod timestamp with time zone DEFAULT now() NOT NULL,
    data json NOT NULL
);


ALTER TABLE public.all_cve OWNER TO glvd;

--
-- Name: deb_cve; Type: TABLE; Schema: public; Owner: glvd
--

CREATE TABLE public.deb_cve (
    dist_id integer NOT NULL,
    cve_id text NOT NULL,
    last_mod timestamp with time zone DEFAULT now() NOT NULL,
    cvss_severity integer,
    deb_source text NOT NULL,
    deb_version public.debversion NOT NULL,
    deb_version_fixed public.debversion,
    debsec_vulnerable boolean NOT NULL,
    data_cpe_match json NOT NULL
);


ALTER TABLE public.deb_cve OWNER TO glvd;

--
-- Name: debsec_cve; Type: TABLE; Schema: public; Owner: glvd
--

CREATE TABLE public.debsec_cve (
    dist_id integer NOT NULL,
    cve_id text NOT NULL,
    last_mod timestamp with time zone DEFAULT now() NOT NULL,
    deb_source text NOT NULL,
    deb_version_fixed public.debversion,
    debsec_tag text,
    debsec_note text
);


ALTER TABLE public.debsec_cve OWNER TO glvd;

--
-- Name: debsrc; Type: TABLE; Schema: public; Owner: glvd
--

CREATE TABLE public.debsrc (
    dist_id integer NOT NULL,
    last_mod timestamp with time zone DEFAULT now() NOT NULL,
    deb_source text NOT NULL,
    deb_version public.debversion NOT NULL
);


ALTER TABLE public.debsrc OWNER TO glvd;

--
-- Name: dist_cpe; Type: TABLE; Schema: public; Owner: glvd
--

CREATE TABLE public.dist_cpe (
    id integer NOT NULL,
    cpe_vendor text NOT NULL,
    cpe_product text NOT NULL,
    cpe_version text NOT NULL,
    deb_codename text NOT NULL
);


ALTER TABLE public.dist_cpe OWNER TO glvd;

--
-- Name: dist_cpe_id_seq; Type: SEQUENCE; Schema: public; Owner: glvd
--

CREATE SEQUENCE public.dist_cpe_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.dist_cpe_id_seq OWNER TO glvd;

--
-- Name: dist_cpe_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: glvd
--

ALTER SEQUENCE public.dist_cpe_id_seq OWNED BY public.dist_cpe.id;


--
-- Name: nvd_cve; Type: TABLE; Schema: public; Owner: glvd
--

CREATE TABLE public.nvd_cve (
    cve_id text NOT NULL,
    last_mod timestamp with time zone NOT NULL,
    data json NOT NULL
);


ALTER TABLE public.nvd_cve OWNER TO glvd;

--
-- Name: dist_cpe id; Type: DEFAULT; Schema: public; Owner: glvd
--

ALTER TABLE ONLY public.dist_cpe ALTER COLUMN id SET DEFAULT nextval('public.dist_cpe_id_seq'::regclass);


--
-- Data for Name: all_cve; Type: TABLE DATA; Schema: public; Owner: glvd
--

COPY public.all_cve (cve_id, last_mod, data) FROM stdin;
CVE-2024-1546	2024-04-29 11:21:35.578569+00	{"id": "CVE-2024-1546", "sourceIdentifier": "security@mozilla.org", "published": "2024-02-20T14:15:08.477", "lastModified": "2024-03-04T09:15:37.650", "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": "When storing and re-accessing data on a networking channel, the length of buffers may have been confused, resulting in an out-of-bounds memory read. This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8."}, {"lang": "es", "value": "Al almacenar y volver a acceder a datos en un canal de red, es posible que se haya confundido la longitud de los bufferse, lo que resulta en una lectura de memoria fuera de los l\\u00edmites. Esta vulnerabilidad afecta a Firefox &lt; 123, Firefox ESR &lt; 115.8 y Thunderbird &lt; 115.8."}], "metrics": {}, "references": [{"url": "https://bugzilla.mozilla.org/show_bug.cgi?id=1843752", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00000.html", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00001.html", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-05/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-06/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-07/", "source": "security@mozilla.org"}], "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.7.0esr-1~deb12u1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": true}, {"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=thunderbird", "deb": {"versionLatest": "1:115.7.0-1~deb12u1", "versionEndExcluding": "1:115.8.0-1"}, "vulnerable": true}, {"criteria": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.8.0esr-1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": false}], "negate": false, "operator": "OR"}]}]}
CVE-2024-1547	2024-04-29 11:21:35.578569+00	{"id": "CVE-2024-1547", "sourceIdentifier": "security@mozilla.org", "published": "2024-02-20T14:15:08.547", "lastModified": "2024-03-04T09:15:37.740", "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": "Through a series of API calls and redirects, an attacker-controlled alert dialog could have been displayed on another website (with the victim website's URL shown). This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8."}, {"lang": "es", "value": "A trav\\u00e9s de una serie de llamadas API y redireccionamientos, se podr\\u00eda haber mostrado un cuadro de di\\u00e1logo de alerta controlado por el atacante en otro sitio web (con la URL del sitio web de la v\\u00edctima mostrada). Esta vulnerabilidad afecta a Firefox &lt; 123, Firefox ESR &lt; 115.8 y Thunderbird &lt; 115.8."}], "metrics": {}, "references": [{"url": "https://bugzilla.mozilla.org/show_bug.cgi?id=1877879", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00000.html", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00001.html", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-05/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-06/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-07/", "source": "security@mozilla.org"}], "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.8.0esr-1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": false}, {"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=thunderbird", "deb": {"versionLatest": "1:115.7.0-1~deb12u1", "versionEndExcluding": "1:115.8.0-1"}, "vulnerable": true}, {"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.7.0esr-1~deb12u1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": true}], "negate": false, "operator": "OR"}]}]}
CVE-2024-1548	2024-04-29 11:21:35.578569+00	{"id": "CVE-2024-1548", "sourceIdentifier": "security@mozilla.org", "published": "2024-02-20T14:15:08.603", "lastModified": "2024-03-04T09:15:37.787", "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": "A website could have obscured the fullscreen notification by using a dropdown select input element. This could have led to user confusion and possible spoofing attacks. This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8."}, {"lang": "es", "value": "Un sitio web podr\\u00eda haber oscurecido la notificaci\\u00f3n de pantalla completa mediante el uso de un elemento de entrada de selecci\\u00f3n desplegable. Esto podr\\u00eda haber generado confusi\\u00f3n en los usuarios y posibles ataques de suplantaci\\u00f3n de identidad. Esta vulnerabilidad afecta a Firefox &lt; 123, Firefox ESR &lt; 115.8 y Thunderbird &lt; 115.8."}], "metrics": {}, "references": [{"url": "https://bugzilla.mozilla.org/show_bug.cgi?id=1832627", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00000.html", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00001.html", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-05/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-06/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-07/", "source": "security@mozilla.org"}], "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=thunderbird", "deb": {"versionLatest": "1:115.7.0-1~deb12u1", "versionEndExcluding": "1:115.8.0-1"}, "vulnerable": true}, {"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.7.0esr-1~deb12u1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": true}, {"criteria": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.8.0esr-1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": false}], "negate": false, "operator": "OR"}]}]}
CVE-2024-1549	2024-04-29 11:21:35.578569+00	{"id": "CVE-2024-1549", "sourceIdentifier": "security@mozilla.org", "published": "2024-02-20T14:15:08.683", "lastModified": "2024-03-04T09:15:37.830", "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": "If a website set a large custom cursor, portions of the cursor could have overlapped with the permission dialog, potentially resulting in user confusion and unexpected granted permissions. This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8."}, {"lang": "es", "value": "Si un sitio web configura un cursor personalizado grande, partes del cursor podr\\u00edan haberse superpuesto con el cuadro de di\\u00e1logo de permisos, lo que podr\\u00eda generar confusi\\u00f3n en el usuario y permisos concedidos inesperados. Esta vulnerabilidad afecta a Firefox &lt; 123, Firefox ESR &lt; 115.8 y Thunderbird &lt; 115.8."}], "metrics": {}, "references": [{"url": "https://bugzilla.mozilla.org/show_bug.cgi?id=1833814", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00000.html", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00001.html", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-05/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-06/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-07/", "source": "security@mozilla.org"}], "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.8.0esr-1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": false}, {"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=thunderbird", "deb": {"versionLatest": "1:115.7.0-1~deb12u1", "versionEndExcluding": "1:115.8.0-1"}, "vulnerable": true}, {"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.7.0esr-1~deb12u1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": true}], "negate": false, "operator": "OR"}]}]}
CVE-2024-1550	2024-04-29 11:21:35.578569+00	{"id": "CVE-2024-1550", "sourceIdentifier": "security@mozilla.org", "published": "2024-02-20T14:15:08.733", "lastModified": "2024-03-04T09:15:37.870", "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": "A malicious website could have used a combination of exiting fullscreen mode and `requestPointerLock` to cause the user's mouse to be re-positioned unexpectedly, which could have led to user confusion and inadvertently granting permissions they did not intend to grant. This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8."}, {"lang": "es", "value": "Un sitio web malicioso podr\\u00eda haber utilizado una combinaci\\u00f3n de salir del modo de pantalla completa y `requestPointerLock` para provocar que el mouse del usuario se reposicionara inesperadamente, lo que podr\\u00eda haber llevado a confusi\\u00f3n al usuario y haber otorgado permisos sin darse cuenta que no ten\\u00eda intenci\\u00f3n de otorgar. Esta vulnerabilidad afecta a Firefox &lt; 123, Firefox ESR &lt; 115.8 y Thunderbird &lt; 115.8."}], "metrics": {}, "references": [{"url": "https://bugzilla.mozilla.org/show_bug.cgi?id=1860065", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00000.html", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00001.html", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-05/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-06/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-07/", "source": "security@mozilla.org"}], "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.7.0esr-1~deb12u1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": true}, {"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=thunderbird", "deb": {"versionLatest": "1:115.7.0-1~deb12u1", "versionEndExcluding": "1:115.8.0-1"}, "vulnerable": true}, {"criteria": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.8.0esr-1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": false}], "negate": false, "operator": "OR"}]}]}
CVE-2024-1551	2024-04-29 11:21:35.578569+00	{"id": "CVE-2024-1551", "sourceIdentifier": "security@mozilla.org", "published": "2024-02-20T14:15:08.790", "lastModified": "2024-03-04T09:15:37.913", "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": "Set-Cookie response headers were being incorrectly honored in multipart HTTP responses. If an attacker could control the Content-Type response header, as well as control part of the response body, they could inject Set-Cookie response headers that would have been honored by the browser. This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8."}, {"lang": "es", "value": "Los encabezados de respuesta Set-Cookie se respetaban incorrectamente en las respuestas HTTP de varias partes. Si un atacante pudiera controlar el encabezado de respuesta Content-Type, as\\u00ed como controlar parte del cuerpo de la respuesta, podr\\u00eda inyectar encabezados de respuesta Set-Cookie que el navegador habr\\u00eda respetado. Esta vulnerabilidad afecta a Firefox &lt; 123, Firefox ESR &lt; 115.8 y Thunderbird &lt; 115.8."}], "metrics": {}, "references": [{"url": "https://bugzilla.mozilla.org/show_bug.cgi?id=1864385", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00000.html", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00001.html", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-05/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-06/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-07/", "source": "security@mozilla.org"}], "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.8.0esr-1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": false}, {"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.7.0esr-1~deb12u1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": true}, {"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=thunderbird", "deb": {"versionLatest": "1:115.7.0-1~deb12u1", "versionEndExcluding": "1:115.8.0-1"}, "vulnerable": true}], "negate": false, "operator": "OR"}]}]}
CVE-2024-1552	2024-04-29 11:21:35.578569+00	{"id": "CVE-2024-1552", "sourceIdentifier": "security@mozilla.org", "published": "2024-02-20T14:15:08.840", "lastModified": "2024-03-04T09:15:37.957", "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": "Incorrect code generation could have led to unexpected numeric conversions and potential undefined behavior.*Note:* This issue only affects 32-bit ARM devices. This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8."}, {"lang": "es", "value": "La generaci\\u00f3n incorrecta de c\\u00f3digo podr\\u00eda haber provocado conversiones num\\u00e9ricas inesperadas y un posible comportamiento indefinido.*Nota:* Este problema solo afecta a los dispositivos ARM de 32 bits. Esta vulnerabilidad afecta a Firefox &lt; 123, Firefox ESR &lt; 115.8 y Thunderbird &lt; 115.8."}], "metrics": {}, "references": [{"url": "https://bugzilla.mozilla.org/show_bug.cgi?id=1874502", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00000.html", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00001.html", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-05/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-06/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-07/", "source": "security@mozilla.org"}], "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.7.0esr-1~deb12u1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": true}, {"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=thunderbird", "deb": {"versionLatest": "1:115.7.0-1~deb12u1", "versionEndExcluding": "1:115.8.0-1"}, "vulnerable": true}, {"criteria": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.8.0esr-1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": false}], "negate": false, "operator": "OR"}]}]}
CVE-2024-1553	2024-04-29 11:21:35.578569+00	{"id": "CVE-2024-1553", "sourceIdentifier": "security@mozilla.org", "published": "2024-02-20T14:15:08.903", "lastModified": "2024-03-04T09:15:37.997", "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": "Memory safety bugs present in Firefox 122, Firefox ESR 115.7, and Thunderbird 115.7. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8."}, {"lang": "es", "value": "Errores de seguridad de la memoria presentes en Firefox 122, Firefox ESR 115.7 y Thunderbird 115.7. Algunos de estos errores mostraron evidencia de corrupci\\u00f3n de memoria y suponemos que con suficiente esfuerzo algunos de ellos podr\\u00edan haberse aprovechado para ejecutar c\\u00f3digo arbitrario. Esta vulnerabilidad afecta a Firefox &lt; 123, Firefox ESR &lt; 115.8 y Thunderbird &lt; 115.8."}], "metrics": {}, "references": [{"url": "https://bugzilla.mozilla.org/buglist.cgi?bug_id=1855686%2C1867982%2C1871498%2C1872296%2C1873521%2C1873577%2C1873597%2C1873866%2C1874080%2C1874740%2C1875795%2C1875906%2C1876425%2C1878211%2C1878286", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00000.html", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00001.html", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-05/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-06/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-07/", "source": "security@mozilla.org"}], "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.8.0esr-1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": false}, {"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.7.0esr-1~deb12u1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": true}, {"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=thunderbird", "deb": {"versionLatest": "1:115.7.0-1~deb12u1", "versionEndExcluding": "1:115.8.0-1"}, "vulnerable": true}], "negate": false, "operator": "OR"}]}]}
CVE-2024-1580	2024-04-29 11:21:35.578569+00	{"id": "CVE-2024-1580", "sourceIdentifier": "cve-coordination@google.com", "published": "2024-02-19T11:15:08.817", "lastModified": "2024-03-27T18:15:09.063", "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": "An integer overflow in dav1d AV1 decoder that can occur when decoding videos with large frame size. This can lead to memory corruption within the AV1 decoder. We recommend upgrading past version 1.4.0 of dav1d.\\n\\n\\n\\n"}, {"lang": "es", "value": "Un desbordamiento de enteros en el decodificador dav1d AV1 que puede ocurrir al decodificar videos con un tama\\u00f1o de cuadro grande. Esto puede provocar da\\u00f1os en la memoria del decodificador AV1. Recomendamos actualizar la versi\\u00f3n anterior 1.4.0 de dav1d."}], "metrics": {"cvssMetricV31": [{"source": "cve-coordination@google.com", "type": "Secondary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L", "attackVector": "ADJACENT_NETWORK", "attackComplexity": "HIGH", "privilegesRequired": "LOW", "userInteraction": "NONE", "scope": "UNCHANGED", "confidentialityImpact": "LOW", "integrityImpact": "HIGH", "availabilityImpact": "LOW", "baseScore": 5.9, "baseSeverity": "MEDIUM"}, "exploitabilityScore": 1.2, "impactScore": 4.7}]}, "weaknesses": [{"source": "cve-coordination@google.com", "type": "Secondary", "description": [{"lang": "en", "value": "CWE-190"}]}], "references": [{"url": "http://seclists.org/fulldisclosure/2024/Mar/36", "source": "cve-coordination@google.com"}, {"url": "http://seclists.org/fulldisclosure/2024/Mar/37", "source": "cve-coordination@google.com"}, {"url": "http://seclists.org/fulldisclosure/2024/Mar/38", "source": "cve-coordination@google.com"}, {"url": "http://seclists.org/fulldisclosure/2024/Mar/39", "source": "cve-coordination@google.com"}, {"url": "http://seclists.org/fulldisclosure/2024/Mar/40", "source": "cve-coordination@google.com"}, {"url": "http://seclists.org/fulldisclosure/2024/Mar/41", "source": "cve-coordination@google.com"}, {"url": "https://code.videolan.org/videolan/dav1d/-/blob/master/NEWS", "source": "cve-coordination@google.com"}, {"url": "https://code.videolan.org/videolan/dav1d/-/releases/1.4.0", "source": "cve-coordination@google.com"}, {"url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5EPMUNDMEBGESOJ2ZNCWYEAYOOEKNWOO/", "source": "cve-coordination@google.com"}, {"url": "https://support.apple.com/kb/HT214093", "source": "cve-coordination@google.com"}, {"url": "https://support.apple.com/kb/HT214094", "source": "cve-coordination@google.com"}, {"url": "https://support.apple.com/kb/HT214095", "source": "cve-coordination@google.com"}, {"url": "https://support.apple.com/kb/HT214096", "source": "cve-coordination@google.com"}, {"url": "https://support.apple.com/kb/HT214097", "source": "cve-coordination@google.com"}, {"url": "https://support.apple.com/kb/HT214098", "source": "cve-coordination@google.com"}], "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=dav1d", "deb": {"versionLatest": "1.0.0-2", "versionEndExcluding": "1.4.0-1"}, "vulnerable": true}, {"criteria": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:deb_source\\\\=dav1d", "deb": {"versionLatest": "1.4.1-1", "versionEndExcluding": "1.4.0-1"}, "vulnerable": false}], "negate": false, "operator": "OR"}]}]}
CVE-2024-1597	2024-04-29 11:21:35.578569+00	{"id": "CVE-2024-1597", "sourceIdentifier": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007", "published": "2024-02-19T13:15:07.740", "lastModified": "2024-04-19T07:15:09.047", "vulnStatus": "Modified", "descriptions": [{"lang": "en", "value": "pgjdbc, the PostgreSQL JDBC Driver, allows attacker to inject SQL if using PreferQueryMode=SIMPLE. Note this is not the default. In the default mode there is no vulnerability. A placeholder for a numeric value must be immediately preceded by a minus. There must be a second placeholder for a string value after the first placeholder; both must be on the same line. By constructing a matching string payload, the attacker can inject SQL to alter the query,bypassing the protections that parameterized queries bring against SQL Injection attacks. Versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 are affected."}, {"lang": "es", "value": "pgjdbc, el controlador JDBC de PostgreSQL, permite al atacante inyectar SQL si usa PreferQueryMode=SIMPLE. Tenga en cuenta que este no es el valor predeterminado. En el modo predeterminado no hay vulnerabilidad. Un comod\\u00edn para un valor num\\u00e9rico debe ir precedido inmediatamente de un signo menos. Debe haber un segundo marcador de posici\\u00f3n para un valor de cadena despu\\u00e9s del primer marcador de posici\\u00f3n; ambos deben estar en la misma l\\u00ednea. Al construir un payload de cadena coincidente, el atacante puede inyectar SQL para alterar la consulta, evitando las protecciones que las consultas parametrizadas brindan contra los ataques de inyecci\\u00f3n SQL. Las versiones anteriores a 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9 y 42.2.8 se ven afectadas."}], "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "attackVector": "NETWORK", "attackComplexity": "LOW", "privilegesRequired": "NONE", "userInteraction": "NONE", "scope": "UNCHANGED", "confidentialityImpact": "HIGH", "integrityImpact": "HIGH", "availabilityImpact": "HIGH", "baseScore": 9.8, "baseSeverity": "CRITICAL"}, "exploitabilityScore": 3.9, "impactScore": 5.9}, {"source": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007", "type": "Secondary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "attackVector": "NETWORK", "attackComplexity": "LOW", "privilegesRequired": "NONE", "userInteraction": "NONE", "scope": "CHANGED", "confidentialityImpact": "HIGH", "integrityImpact": "HIGH", "availabilityImpact": "HIGH", "baseScore": 10.0, "baseSeverity": "CRITICAL"}, "exploitabilityScore": 3.9, "impactScore": 6.0}]}, "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-89"}]}, {"source": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007", "type": "Secondary", "description": [{"lang": "en", "value": "CWE-89"}]}], "configurations": [{"nodes": [{"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:a:postgresql:postgresql_jdbc_driver:*:*:*:*:*:*:*:*", "versionEndExcluding": "42.2.28", "matchCriteriaId": "51F0F89A-760E-4592-B142-0A28A0BCD61F"}, {"vulnerable": true, "criteria": "cpe:2.3:a:postgresql:postgresql_jdbc_driver:*:*:*:*:*:*:*:*", "versionStartIncluding": "42.3.0", "versionEndExcluding": "42.3.9", "matchCriteriaId": "9AF8DB08-81BB-48AD-85E5-B05220E49EA6"}, {"vulnerable": true, "criteria": "cpe:2.3:a:postgresql:postgresql_jdbc_driver:*:*:*:*:*:*:*:*", "versionStartIncluding": "42.4.0", "versionEndExcluding": "42.4.4", "matchCriteriaId": "3453F9D3-2F9E-493F-8993-4F2A9B9E53F2"}, {"vulnerable": true, "criteria": "cpe:2.3:a:postgresql:postgresql_jdbc_driver:*:*:*:*:*:*:*:*", "versionStartIncluding": "42.5.0", "versionEndExcluding": "42.5.5", "matchCriteriaId": "99C07B95-DBCC-4DB2-9896-2F7A98CEC91B"}, {"vulnerable": true, "criteria": "cpe:2.3:a:postgresql:postgresql_jdbc_driver:*:*:*:*:*:*:*:*", "versionStartIncluding": "42.6.0", "versionEndExcluding": "42.6.1", "matchCriteriaId": "F30ED3D3-46C8-49D8-BF6F-B804CF8FF02C"}, {"vulnerable": true, "criteria": "cpe:2.3:a:postgresql:postgresql_jdbc_driver:*:*:*:*:*:*:*:*", "versionStartIncluding": "42.7.0", "versionEndExcluding": "42.7.2", "matchCriteriaId": "8F88E552-40D4-4287-9357-00D352133ADC"}]}]}, {"nodes": [{"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:o:fedoraproject:fedora:40:*:*:*:*:*:*:*", "matchCriteriaId": "CA277A6C-83EC-4536-9125-97B84C4FAF59"}]}]}, {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:deb_source\\\\=libpgjava", "deb": {"versionLatest": "42.7.3-1", "cvssSeverity": "CRITICAL", "versionEndExcluding": "42.7.2-1"}, "vulnerable": false}, {"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=libpgjava", "deb": {"versionLatest": "42.5.4-1", "cvssSeverity": "CRITICAL", "versionEndExcluding": "42.7.2-1"}, "vulnerable": true}], "negate": false, "operator": "OR"}]}], "references": [{"url": "https://github.com/pgjdbc/pgjdbc/security/advisories/GHSA-24rp-q3w6-vc56", "source": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007", "tags": ["Third Party Advisory"]}, {"url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TZQTSMESZD2RJ5XBPSXH3TIQVUW5DIUU/", "source": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007", "tags": ["Mailing List", "Third Party Advisory"]}, {"url": "https://security.netapp.com/advisory/ntap-20240419-0008/", "source": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007"}, {"url": "https://www.enterprisedb.com/docs/jdbc_connector/latest/01_jdbc_rel_notes/", "source": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007", "tags": ["Release Notes"]}, {"url": "https://www.enterprisedb.com/docs/security/assessments/cve-2024-1597/", "source": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007", "tags": ["Third Party Advisory"]}]}
\.


--
-- Data for Name: deb_cve; Type: TABLE DATA; Schema: public; Owner: glvd
--

COPY public.deb_cve (dist_id, cve_id, last_mod, cvss_severity, deb_source, deb_version, deb_version_fixed, debsec_vulnerable, data_cpe_match) FROM stdin;
1	CVE-2024-1546	2024-04-29 11:21:21.425622+00	\N	firefox-esr	115.8.0esr-1	115.8.0esr-1	f	{"criteria": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.8.0esr-1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": false}
1	CVE-2024-1547	2024-04-29 11:21:21.425622+00	\N	firefox-esr	115.8.0esr-1	115.8.0esr-1	f	{"criteria": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.8.0esr-1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": false}
1	CVE-2024-1548	2024-04-29 11:21:21.425622+00	\N	firefox-esr	115.8.0esr-1	115.8.0esr-1	f	{"criteria": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.8.0esr-1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": false}
1	CVE-2024-1549	2024-04-29 11:21:21.425622+00	\N	firefox-esr	115.8.0esr-1	115.8.0esr-1	f	{"criteria": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.8.0esr-1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": false}
1	CVE-2024-1550	2024-04-29 11:21:21.425622+00	\N	firefox-esr	115.8.0esr-1	115.8.0esr-1	f	{"criteria": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.8.0esr-1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": false}
1	CVE-2024-1551	2024-04-29 11:21:21.425622+00	\N	firefox-esr	115.8.0esr-1	115.8.0esr-1	f	{"criteria": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.8.0esr-1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": false}
1	CVE-2024-1552	2024-04-29 11:21:21.425622+00	\N	firefox-esr	115.8.0esr-1	115.8.0esr-1	f	{"criteria": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.8.0esr-1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": false}
1	CVE-2024-1553	2024-04-29 11:21:21.425622+00	\N	firefox-esr	115.8.0esr-1	115.8.0esr-1	f	{"criteria": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.8.0esr-1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": false}
1	CVE-2024-1580	2024-04-29 11:21:21.425622+00	\N	dav1d	1.4.1-1	1.4.0-1	f	{"criteria": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:deb_source\\\\=dav1d", "deb": {"versionLatest": "1.4.1-1", "versionEndExcluding": "1.4.0-1"}, "vulnerable": false}
1	CVE-2024-1597	2024-04-29 11:21:21.425622+00	5	libpgjava	42.7.3-1	42.7.2-1	f	{"criteria": "cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:deb_source\\\\=libpgjava", "deb": {"versionLatest": "42.7.3-1", "cvssSeverity": "CRITICAL", "versionEndExcluding": "42.7.2-1"}, "vulnerable": false}
2	CVE-2024-1546	2024-04-29 11:21:21.425622+00	\N	firefox-esr	115.7.0esr-1~deb12u1	115.8.0esr-1	t	{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.7.0esr-1~deb12u1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": true}
2	CVE-2024-1546	2024-04-29 11:21:21.425622+00	\N	thunderbird	1:115.7.0-1~deb12u1	1:115.8.0-1	t	{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=thunderbird", "deb": {"versionLatest": "1:115.7.0-1~deb12u1", "versionEndExcluding": "1:115.8.0-1"}, "vulnerable": true}
2	CVE-2024-1547	2024-04-29 11:21:21.425622+00	\N	firefox-esr	115.7.0esr-1~deb12u1	115.8.0esr-1	t	{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.7.0esr-1~deb12u1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": true}
2	CVE-2024-1547	2024-04-29 11:21:21.425622+00	\N	thunderbird	1:115.7.0-1~deb12u1	1:115.8.0-1	t	{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=thunderbird", "deb": {"versionLatest": "1:115.7.0-1~deb12u1", "versionEndExcluding": "1:115.8.0-1"}, "vulnerable": true}
2	CVE-2024-1548	2024-04-29 11:21:21.425622+00	\N	firefox-esr	115.7.0esr-1~deb12u1	115.8.0esr-1	t	{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.7.0esr-1~deb12u1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": true}
2	CVE-2024-1548	2024-04-29 11:21:21.425622+00	\N	thunderbird	1:115.7.0-1~deb12u1	1:115.8.0-1	t	{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=thunderbird", "deb": {"versionLatest": "1:115.7.0-1~deb12u1", "versionEndExcluding": "1:115.8.0-1"}, "vulnerable": true}
2	CVE-2024-1549	2024-04-29 11:21:21.425622+00	\N	firefox-esr	115.7.0esr-1~deb12u1	115.8.0esr-1	t	{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.7.0esr-1~deb12u1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": true}
2	CVE-2024-1549	2024-04-29 11:21:21.425622+00	\N	thunderbird	1:115.7.0-1~deb12u1	1:115.8.0-1	t	{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=thunderbird", "deb": {"versionLatest": "1:115.7.0-1~deb12u1", "versionEndExcluding": "1:115.8.0-1"}, "vulnerable": true}
2	CVE-2024-1550	2024-04-29 11:21:21.425622+00	\N	firefox-esr	115.7.0esr-1~deb12u1	115.8.0esr-1	t	{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.7.0esr-1~deb12u1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": true}
2	CVE-2024-1550	2024-04-29 11:21:21.425622+00	\N	thunderbird	1:115.7.0-1~deb12u1	1:115.8.0-1	t	{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=thunderbird", "deb": {"versionLatest": "1:115.7.0-1~deb12u1", "versionEndExcluding": "1:115.8.0-1"}, "vulnerable": true}
2	CVE-2024-1551	2024-04-29 11:21:21.425622+00	\N	firefox-esr	115.7.0esr-1~deb12u1	115.8.0esr-1	t	{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.7.0esr-1~deb12u1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": true}
2	CVE-2024-1551	2024-04-29 11:21:21.425622+00	\N	thunderbird	1:115.7.0-1~deb12u1	1:115.8.0-1	t	{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=thunderbird", "deb": {"versionLatest": "1:115.7.0-1~deb12u1", "versionEndExcluding": "1:115.8.0-1"}, "vulnerable": true}
2	CVE-2024-1552	2024-04-29 11:21:21.425622+00	\N	firefox-esr	115.7.0esr-1~deb12u1	115.8.0esr-1	t	{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.7.0esr-1~deb12u1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": true}
2	CVE-2024-1552	2024-04-29 11:21:21.425622+00	\N	thunderbird	1:115.7.0-1~deb12u1	1:115.8.0-1	t	{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=thunderbird", "deb": {"versionLatest": "1:115.7.0-1~deb12u1", "versionEndExcluding": "1:115.8.0-1"}, "vulnerable": true}
2	CVE-2024-1553	2024-04-29 11:21:21.425622+00	\N	firefox-esr	115.7.0esr-1~deb12u1	115.8.0esr-1	t	{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=firefox-esr", "deb": {"versionLatest": "115.7.0esr-1~deb12u1", "versionEndExcluding": "115.8.0esr-1"}, "vulnerable": true}
2	CVE-2024-1553	2024-04-29 11:21:21.425622+00	\N	thunderbird	1:115.7.0-1~deb12u1	1:115.8.0-1	t	{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=thunderbird", "deb": {"versionLatest": "1:115.7.0-1~deb12u1", "versionEndExcluding": "1:115.8.0-1"}, "vulnerable": true}
2	CVE-2024-1580	2024-04-29 11:21:21.425622+00	\N	dav1d	1.0.0-2	1.4.0-1	t	{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=dav1d", "deb": {"versionLatest": "1.0.0-2", "versionEndExcluding": "1.4.0-1"}, "vulnerable": true}
2	CVE-2024-1597	2024-04-29 11:21:21.425622+00	5	libpgjava	42.5.4-1	42.7.2-1	t	{"criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:deb_source\\\\=libpgjava", "deb": {"versionLatest": "42.5.4-1", "cvssSeverity": "CRITICAL", "versionEndExcluding": "42.7.2-1"}, "vulnerable": true}
\.


--
-- Data for Name: debsec_cve; Type: TABLE DATA; Schema: public; Owner: glvd
--

COPY public.debsec_cve (dist_id, cve_id, last_mod, deb_source, deb_version_fixed, debsec_tag, debsec_note) FROM stdin;
3	CVE-2024-1546	2024-04-29 10:52:19.338308+00	firefox	123.0-1	\N	\N
3	CVE-2024-1546	2024-04-29 10:52:19.338308+00	firefox-esr	115.8.0esr-1	\N	\N
3	CVE-2024-1546	2024-04-29 10:52:19.338308+00	thunderbird	1:115.8.0-1	\N	\N
3	CVE-2024-1547	2024-04-29 10:52:19.338308+00	firefox	123.0-1	\N	\N
3	CVE-2024-1547	2024-04-29 10:52:19.338308+00	firefox-esr	115.8.0esr-1	\N	\N
3	CVE-2024-1547	2024-04-29 10:52:19.338308+00	thunderbird	1:115.8.0-1	\N	\N
3	CVE-2024-1548	2024-04-29 10:52:19.338308+00	firefox	123.0-1	\N	\N
3	CVE-2024-1548	2024-04-29 10:52:19.338308+00	firefox-esr	115.8.0esr-1	\N	\N
3	CVE-2024-1548	2024-04-29 10:52:19.338308+00	thunderbird	1:115.8.0-1	\N	\N
3	CVE-2024-1549	2024-04-29 10:52:19.338308+00	firefox	123.0-1	\N	\N
3	CVE-2024-1549	2024-04-29 10:52:19.338308+00	firefox-esr	115.8.0esr-1	\N	\N
3	CVE-2024-1549	2024-04-29 10:52:19.338308+00	thunderbird	1:115.8.0-1	\N	\N
3	CVE-2024-1550	2024-04-29 10:52:19.338308+00	firefox	123.0-1	\N	\N
3	CVE-2024-1550	2024-04-29 10:52:19.338308+00	firefox-esr	115.8.0esr-1	\N	\N
3	CVE-2024-1550	2024-04-29 10:52:19.338308+00	thunderbird	1:115.8.0-1	\N	\N
3	CVE-2024-1551	2024-04-29 10:52:19.338308+00	firefox	123.0-1	\N	\N
3	CVE-2024-1551	2024-04-29 10:52:19.338308+00	firefox-esr	115.8.0esr-1	\N	\N
3	CVE-2024-1551	2024-04-29 10:52:19.338308+00	thunderbird	1:115.8.0-1	\N	\N
3	CVE-2024-1552	2024-04-29 10:52:19.338308+00	firefox	123.0-1	\N	\N
3	CVE-2024-1552	2024-04-29 10:52:19.338308+00	firefox-esr	115.8.0esr-1	\N	\N
3	CVE-2024-1552	2024-04-29 10:52:19.338308+00	thunderbird	1:115.8.0-1	\N	\N
3	CVE-2024-1553	2024-04-29 10:52:19.338308+00	firefox	123.0-1	\N	\N
3	CVE-2024-1553	2024-04-29 10:52:19.338308+00	firefox-esr	115.8.0esr-1	\N	\N
3	CVE-2024-1553	2024-04-29 10:52:19.338308+00	thunderbird	1:115.8.0-1	\N	\N
3	CVE-2024-1580	2024-04-29 10:52:19.338308+00	dav1d	1.4.0-1	\N	bug #1064310
3	CVE-2024-1597	2024-04-29 10:52:19.338308+00	libpgjava	42.7.2-1	\N	\N
\.


--
-- Data for Name: debsrc; Type: TABLE DATA; Schema: public; Owner: glvd
--

COPY public.debsrc (dist_id, last_mod, deb_source, deb_version) FROM stdin;
1	2024-04-29 10:52:11.502104+00	dav1d	1.4.1-1
1	2024-04-29 10:52:11.502104+00	firefox-esr	115.8.0esr-1
1	2024-04-29 10:52:11.502104+00	libpgjava	42.7.3-1
2	2024-04-29 10:52:14.687966+00	dav1d	1.0.0-2
2	2024-04-29 10:52:14.687966+00	firefox-esr	115.7.0esr-1~deb12u1
2	2024-04-29 10:52:14.687966+00	libpgjava	42.5.4-1
2	2024-04-29 10:52:14.687966+00	thunderbird	1:115.7.0-1~deb12u1
\.


--
-- Data for Name: dist_cpe; Type: TABLE DATA; Schema: public; Owner: glvd
--

COPY public.dist_cpe (id, cpe_vendor, cpe_product, cpe_version, deb_codename) FROM stdin;
1	debian	debian_linux	13	trixie
2	debian	debian_linux	12	bookworm
3	debian	debian_linux		
4	debian	debian_linux	11	bullseye
5	debian	debian_linux	10	buster
6	debian	debian_linux	9	stretch
7	debian	debian_linux	8	jessie
8	debian	debian_linux	7	wheezy
9	debian	debian_linux	6.0	squeeze
10	debian	debian_linux	5.0	lenny
11	debian	debian_linux	4.0	etch
12	debian	debian_linux	3.1	sarge
13	debian	debian_linux	3.0	woody
\.


--
-- Data for Name: nvd_cve; Type: TABLE DATA; Schema: public; Owner: glvd
--

COPY public.nvd_cve (cve_id, last_mod, data) FROM stdin;
CVE-2024-1546	2024-03-04 09:15:37.65+00	{"id": "CVE-2024-1546", "sourceIdentifier": "security@mozilla.org", "published": "2024-02-20T14:15:08.477", "lastModified": "2024-03-04T09:15:37.650", "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": "When storing and re-accessing data on a networking channel, the length of buffers may have been confused, resulting in an out-of-bounds memory read. This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8."}, {"lang": "es", "value": "Al almacenar y volver a acceder a datos en un canal de red, es posible que se haya confundido la longitud de los bufferse, lo que resulta en una lectura de memoria fuera de los l\\u00edmites. Esta vulnerabilidad afecta a Firefox &lt; 123, Firefox ESR &lt; 115.8 y Thunderbird &lt; 115.8."}], "metrics": {}, "references": [{"url": "https://bugzilla.mozilla.org/show_bug.cgi?id=1843752", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00000.html", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00001.html", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-05/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-06/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-07/", "source": "security@mozilla.org"}]}
CVE-2024-1547	2024-03-04 09:15:37.74+00	{"id": "CVE-2024-1547", "sourceIdentifier": "security@mozilla.org", "published": "2024-02-20T14:15:08.547", "lastModified": "2024-03-04T09:15:37.740", "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": "Through a series of API calls and redirects, an attacker-controlled alert dialog could have been displayed on another website (with the victim website's URL shown). This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8."}, {"lang": "es", "value": "A trav\\u00e9s de una serie de llamadas API y redireccionamientos, se podr\\u00eda haber mostrado un cuadro de di\\u00e1logo de alerta controlado por el atacante en otro sitio web (con la URL del sitio web de la v\\u00edctima mostrada). Esta vulnerabilidad afecta a Firefox &lt; 123, Firefox ESR &lt; 115.8 y Thunderbird &lt; 115.8."}], "metrics": {}, "references": [{"url": "https://bugzilla.mozilla.org/show_bug.cgi?id=1877879", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00000.html", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00001.html", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-05/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-06/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-07/", "source": "security@mozilla.org"}]}
CVE-2024-1548	2024-03-04 09:15:37.787+00	{"id": "CVE-2024-1548", "sourceIdentifier": "security@mozilla.org", "published": "2024-02-20T14:15:08.603", "lastModified": "2024-03-04T09:15:37.787", "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": "A website could have obscured the fullscreen notification by using a dropdown select input element. This could have led to user confusion and possible spoofing attacks. This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8."}, {"lang": "es", "value": "Un sitio web podr\\u00eda haber oscurecido la notificaci\\u00f3n de pantalla completa mediante el uso de un elemento de entrada de selecci\\u00f3n desplegable. Esto podr\\u00eda haber generado confusi\\u00f3n en los usuarios y posibles ataques de suplantaci\\u00f3n de identidad. Esta vulnerabilidad afecta a Firefox &lt; 123, Firefox ESR &lt; 115.8 y Thunderbird &lt; 115.8."}], "metrics": {}, "references": [{"url": "https://bugzilla.mozilla.org/show_bug.cgi?id=1832627", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00000.html", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00001.html", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-05/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-06/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-07/", "source": "security@mozilla.org"}]}
CVE-2024-1549	2024-03-04 09:15:37.83+00	{"id": "CVE-2024-1549", "sourceIdentifier": "security@mozilla.org", "published": "2024-02-20T14:15:08.683", "lastModified": "2024-03-04T09:15:37.830", "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": "If a website set a large custom cursor, portions of the cursor could have overlapped with the permission dialog, potentially resulting in user confusion and unexpected granted permissions. This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8."}, {"lang": "es", "value": "Si un sitio web configura un cursor personalizado grande, partes del cursor podr\\u00edan haberse superpuesto con el cuadro de di\\u00e1logo de permisos, lo que podr\\u00eda generar confusi\\u00f3n en el usuario y permisos concedidos inesperados. Esta vulnerabilidad afecta a Firefox &lt; 123, Firefox ESR &lt; 115.8 y Thunderbird &lt; 115.8."}], "metrics": {}, "references": [{"url": "https://bugzilla.mozilla.org/show_bug.cgi?id=1833814", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00000.html", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00001.html", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-05/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-06/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-07/", "source": "security@mozilla.org"}]}
CVE-2024-1550	2024-03-04 09:15:37.87+00	{"id": "CVE-2024-1550", "sourceIdentifier": "security@mozilla.org", "published": "2024-02-20T14:15:08.733", "lastModified": "2024-03-04T09:15:37.870", "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": "A malicious website could have used a combination of exiting fullscreen mode and `requestPointerLock` to cause the user's mouse to be re-positioned unexpectedly, which could have led to user confusion and inadvertently granting permissions they did not intend to grant. This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8."}, {"lang": "es", "value": "Un sitio web malicioso podr\\u00eda haber utilizado una combinaci\\u00f3n de salir del modo de pantalla completa y `requestPointerLock` para provocar que el mouse del usuario se reposicionara inesperadamente, lo que podr\\u00eda haber llevado a confusi\\u00f3n al usuario y haber otorgado permisos sin darse cuenta que no ten\\u00eda intenci\\u00f3n de otorgar. Esta vulnerabilidad afecta a Firefox &lt; 123, Firefox ESR &lt; 115.8 y Thunderbird &lt; 115.8."}], "metrics": {}, "references": [{"url": "https://bugzilla.mozilla.org/show_bug.cgi?id=1860065", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00000.html", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00001.html", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-05/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-06/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-07/", "source": "security@mozilla.org"}]}
CVE-2024-1551	2024-03-04 09:15:37.913+00	{"id": "CVE-2024-1551", "sourceIdentifier": "security@mozilla.org", "published": "2024-02-20T14:15:08.790", "lastModified": "2024-03-04T09:15:37.913", "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": "Set-Cookie response headers were being incorrectly honored in multipart HTTP responses. If an attacker could control the Content-Type response header, as well as control part of the response body, they could inject Set-Cookie response headers that would have been honored by the browser. This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8."}, {"lang": "es", "value": "Los encabezados de respuesta Set-Cookie se respetaban incorrectamente en las respuestas HTTP de varias partes. Si un atacante pudiera controlar el encabezado de respuesta Content-Type, as\\u00ed como controlar parte del cuerpo de la respuesta, podr\\u00eda inyectar encabezados de respuesta Set-Cookie que el navegador habr\\u00eda respetado. Esta vulnerabilidad afecta a Firefox &lt; 123, Firefox ESR &lt; 115.8 y Thunderbird &lt; 115.8."}], "metrics": {}, "references": [{"url": "https://bugzilla.mozilla.org/show_bug.cgi?id=1864385", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00000.html", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00001.html", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-05/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-06/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-07/", "source": "security@mozilla.org"}]}
CVE-2024-1552	2024-03-04 09:15:37.957+00	{"id": "CVE-2024-1552", "sourceIdentifier": "security@mozilla.org", "published": "2024-02-20T14:15:08.840", "lastModified": "2024-03-04T09:15:37.957", "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": "Incorrect code generation could have led to unexpected numeric conversions and potential undefined behavior.*Note:* This issue only affects 32-bit ARM devices. This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8."}, {"lang": "es", "value": "La generaci\\u00f3n incorrecta de c\\u00f3digo podr\\u00eda haber provocado conversiones num\\u00e9ricas inesperadas y un posible comportamiento indefinido.*Nota:* Este problema solo afecta a los dispositivos ARM de 32 bits. Esta vulnerabilidad afecta a Firefox &lt; 123, Firefox ESR &lt; 115.8 y Thunderbird &lt; 115.8."}], "metrics": {}, "references": [{"url": "https://bugzilla.mozilla.org/show_bug.cgi?id=1874502", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00000.html", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00001.html", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-05/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-06/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-07/", "source": "security@mozilla.org"}]}
CVE-2024-1553	2024-03-04 09:15:37.997+00	{"id": "CVE-2024-1553", "sourceIdentifier": "security@mozilla.org", "published": "2024-02-20T14:15:08.903", "lastModified": "2024-03-04T09:15:37.997", "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": "Memory safety bugs present in Firefox 122, Firefox ESR 115.7, and Thunderbird 115.7. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8."}, {"lang": "es", "value": "Errores de seguridad de la memoria presentes en Firefox 122, Firefox ESR 115.7 y Thunderbird 115.7. Algunos de estos errores mostraron evidencia de corrupci\\u00f3n de memoria y suponemos que con suficiente esfuerzo algunos de ellos podr\\u00edan haberse aprovechado para ejecutar c\\u00f3digo arbitrario. Esta vulnerabilidad afecta a Firefox &lt; 123, Firefox ESR &lt; 115.8 y Thunderbird &lt; 115.8."}], "metrics": {}, "references": [{"url": "https://bugzilla.mozilla.org/buglist.cgi?bug_id=1855686%2C1867982%2C1871498%2C1872296%2C1873521%2C1873577%2C1873597%2C1873866%2C1874080%2C1874740%2C1875795%2C1875906%2C1876425%2C1878211%2C1878286", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00000.html", "source": "security@mozilla.org"}, {"url": "https://lists.debian.org/debian-lts-announce/2024/03/msg00001.html", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-05/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-06/", "source": "security@mozilla.org"}, {"url": "https://www.mozilla.org/security/advisories/mfsa2024-07/", "source": "security@mozilla.org"}]}
CVE-2024-1580	2024-03-27 18:15:09.063+00	{"id": "CVE-2024-1580", "sourceIdentifier": "cve-coordination@google.com", "published": "2024-02-19T11:15:08.817", "lastModified": "2024-03-27T18:15:09.063", "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": "An integer overflow in dav1d AV1 decoder that can occur when decoding videos with large frame size. This can lead to memory corruption within the AV1 decoder. We recommend upgrading past version 1.4.0 of dav1d.\\n\\n\\n\\n"}, {"lang": "es", "value": "Un desbordamiento de enteros en el decodificador dav1d AV1 que puede ocurrir al decodificar videos con un tama\\u00f1o de cuadro grande. Esto puede provocar da\\u00f1os en la memoria del decodificador AV1. Recomendamos actualizar la versi\\u00f3n anterior 1.4.0 de dav1d."}], "metrics": {"cvssMetricV31": [{"source": "cve-coordination@google.com", "type": "Secondary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L", "attackVector": "ADJACENT_NETWORK", "attackComplexity": "HIGH", "privilegesRequired": "LOW", "userInteraction": "NONE", "scope": "UNCHANGED", "confidentialityImpact": "LOW", "integrityImpact": "HIGH", "availabilityImpact": "LOW", "baseScore": 5.9, "baseSeverity": "MEDIUM"}, "exploitabilityScore": 1.2, "impactScore": 4.7}]}, "weaknesses": [{"source": "cve-coordination@google.com", "type": "Secondary", "description": [{"lang": "en", "value": "CWE-190"}]}], "references": [{"url": "http://seclists.org/fulldisclosure/2024/Mar/36", "source": "cve-coordination@google.com"}, {"url": "http://seclists.org/fulldisclosure/2024/Mar/37", "source": "cve-coordination@google.com"}, {"url": "http://seclists.org/fulldisclosure/2024/Mar/38", "source": "cve-coordination@google.com"}, {"url": "http://seclists.org/fulldisclosure/2024/Mar/39", "source": "cve-coordination@google.com"}, {"url": "http://seclists.org/fulldisclosure/2024/Mar/40", "source": "cve-coordination@google.com"}, {"url": "http://seclists.org/fulldisclosure/2024/Mar/41", "source": "cve-coordination@google.com"}, {"url": "https://code.videolan.org/videolan/dav1d/-/blob/master/NEWS", "source": "cve-coordination@google.com"}, {"url": "https://code.videolan.org/videolan/dav1d/-/releases/1.4.0", "source": "cve-coordination@google.com"}, {"url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5EPMUNDMEBGESOJ2ZNCWYEAYOOEKNWOO/", "source": "cve-coordination@google.com"}, {"url": "https://support.apple.com/kb/HT214093", "source": "cve-coordination@google.com"}, {"url": "https://support.apple.com/kb/HT214094", "source": "cve-coordination@google.com"}, {"url": "https://support.apple.com/kb/HT214095", "source": "cve-coordination@google.com"}, {"url": "https://support.apple.com/kb/HT214096", "source": "cve-coordination@google.com"}, {"url": "https://support.apple.com/kb/HT214097", "source": "cve-coordination@google.com"}, {"url": "https://support.apple.com/kb/HT214098", "source": "cve-coordination@google.com"}]}
CVE-2024-1597	2024-04-19 07:15:09.047+00	{"id": "CVE-2024-1597", "sourceIdentifier": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007", "published": "2024-02-19T13:15:07.740", "lastModified": "2024-04-19T07:15:09.047", "vulnStatus": "Modified", "descriptions": [{"lang": "en", "value": "pgjdbc, the PostgreSQL JDBC Driver, allows attacker to inject SQL if using PreferQueryMode=SIMPLE. Note this is not the default. In the default mode there is no vulnerability. A placeholder for a numeric value must be immediately preceded by a minus. There must be a second placeholder for a string value after the first placeholder; both must be on the same line. By constructing a matching string payload, the attacker can inject SQL to alter the query,bypassing the protections that parameterized queries bring against SQL Injection attacks. Versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.28 are affected."}, {"lang": "es", "value": "pgjdbc, el controlador JDBC de PostgreSQL, permite al atacante inyectar SQL si usa PreferQueryMode=SIMPLE. Tenga en cuenta que este no es el valor predeterminado. En el modo predeterminado no hay vulnerabilidad. Un comod\\u00edn para un valor num\\u00e9rico debe ir precedido inmediatamente de un signo menos. Debe haber un segundo marcador de posici\\u00f3n para un valor de cadena despu\\u00e9s del primer marcador de posici\\u00f3n; ambos deben estar en la misma l\\u00ednea. Al construir un payload de cadena coincidente, el atacante puede inyectar SQL para alterar la consulta, evitando las protecciones que las consultas parametrizadas brindan contra los ataques de inyecci\\u00f3n SQL. Las versiones anteriores a 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9 y 42.2.8 se ven afectadas."}], "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "attackVector": "NETWORK", "attackComplexity": "LOW", "privilegesRequired": "NONE", "userInteraction": "NONE", "scope": "UNCHANGED", "confidentialityImpact": "HIGH", "integrityImpact": "HIGH", "availabilityImpact": "HIGH", "baseScore": 9.8, "baseSeverity": "CRITICAL"}, "exploitabilityScore": 3.9, "impactScore": 5.9}, {"source": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007", "type": "Secondary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "attackVector": "NETWORK", "attackComplexity": "LOW", "privilegesRequired": "NONE", "userInteraction": "NONE", "scope": "CHANGED", "confidentialityImpact": "HIGH", "integrityImpact": "HIGH", "availabilityImpact": "HIGH", "baseScore": 10.0, "baseSeverity": "CRITICAL"}, "exploitabilityScore": 3.9, "impactScore": 6.0}]}, "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-89"}]}, {"source": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007", "type": "Secondary", "description": [{"lang": "en", "value": "CWE-89"}]}], "configurations": [{"nodes": [{"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:a:postgresql:postgresql_jdbc_driver:*:*:*:*:*:*:*:*", "versionEndExcluding": "42.2.28", "matchCriteriaId": "51F0F89A-760E-4592-B142-0A28A0BCD61F"}, {"vulnerable": true, "criteria": "cpe:2.3:a:postgresql:postgresql_jdbc_driver:*:*:*:*:*:*:*:*", "versionStartIncluding": "42.3.0", "versionEndExcluding": "42.3.9", "matchCriteriaId": "9AF8DB08-81BB-48AD-85E5-B05220E49EA6"}, {"vulnerable": true, "criteria": "cpe:2.3:a:postgresql:postgresql_jdbc_driver:*:*:*:*:*:*:*:*", "versionStartIncluding": "42.4.0", "versionEndExcluding": "42.4.4", "matchCriteriaId": "3453F9D3-2F9E-493F-8993-4F2A9B9E53F2"}, {"vulnerable": true, "criteria": "cpe:2.3:a:postgresql:postgresql_jdbc_driver:*:*:*:*:*:*:*:*", "versionStartIncluding": "42.5.0", "versionEndExcluding": "42.5.5", "matchCriteriaId": "99C07B95-DBCC-4DB2-9896-2F7A98CEC91B"}, {"vulnerable": true, "criteria": "cpe:2.3:a:postgresql:postgresql_jdbc_driver:*:*:*:*:*:*:*:*", "versionStartIncluding": "42.6.0", "versionEndExcluding": "42.6.1", "matchCriteriaId": "F30ED3D3-46C8-49D8-BF6F-B804CF8FF02C"}, {"vulnerable": true, "criteria": "cpe:2.3:a:postgresql:postgresql_jdbc_driver:*:*:*:*:*:*:*:*", "versionStartIncluding": "42.7.0", "versionEndExcluding": "42.7.2", "matchCriteriaId": "8F88E552-40D4-4287-9357-00D352133ADC"}]}]}, {"nodes": [{"operator": "OR", "negate": false, "cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:o:fedoraproject:fedora:40:*:*:*:*:*:*:*", "matchCriteriaId": "CA277A6C-83EC-4536-9125-97B84C4FAF59"}]}]}], "references": [{"url": "https://github.com/pgjdbc/pgjdbc/security/advisories/GHSA-24rp-q3w6-vc56", "source": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007", "tags": ["Third Party Advisory"]}, {"url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TZQTSMESZD2RJ5XBPSXH3TIQVUW5DIUU/", "source": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007", "tags": ["Mailing List", "Third Party Advisory"]}, {"url": "https://security.netapp.com/advisory/ntap-20240419-0008/", "source": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007"}, {"url": "https://www.enterprisedb.com/docs/jdbc_connector/latest/01_jdbc_rel_notes/", "source": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007", "tags": ["Release Notes"]}, {"url": "https://www.enterprisedb.com/docs/security/assessments/cve-2024-1597/", "source": "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007", "tags": ["Third Party Advisory"]}]}
\.


--
-- Name: dist_cpe_id_seq; Type: SEQUENCE SET; Schema: public; Owner: glvd
--

SELECT pg_catalog.setval('public.dist_cpe_id_seq', 13, true);


--
-- Name: all_cve all_cve_pkey; Type: CONSTRAINT; Schema: public; Owner: glvd
--

ALTER TABLE ONLY public.all_cve
    ADD CONSTRAINT all_cve_pkey PRIMARY KEY (cve_id);


--
-- Name: deb_cve deb_cve_pkey; Type: CONSTRAINT; Schema: public; Owner: glvd
--

ALTER TABLE ONLY public.deb_cve
    ADD CONSTRAINT deb_cve_pkey PRIMARY KEY (dist_id, cve_id, deb_source);


--
-- Name: debsec_cve debsec_cve_pkey; Type: CONSTRAINT; Schema: public; Owner: glvd
--

ALTER TABLE ONLY public.debsec_cve
    ADD CONSTRAINT debsec_cve_pkey PRIMARY KEY (dist_id, cve_id, deb_source);


--
-- Name: debsrc debsrc_pkey; Type: CONSTRAINT; Schema: public; Owner: glvd
--

ALTER TABLE ONLY public.debsrc
    ADD CONSTRAINT debsrc_pkey PRIMARY KEY (dist_id, deb_source);


--
-- Name: dist_cpe dist_cpe_pkey; Type: CONSTRAINT; Schema: public; Owner: glvd
--

ALTER TABLE ONLY public.dist_cpe
    ADD CONSTRAINT dist_cpe_pkey PRIMARY KEY (id);


--
-- Name: nvd_cve nvd_cve_pkey; Type: CONSTRAINT; Schema: public; Owner: glvd
--

ALTER TABLE ONLY public.nvd_cve
    ADD CONSTRAINT nvd_cve_pkey PRIMARY KEY (cve_id);


--
-- Name: deb_cve_search; Type: INDEX; Schema: public; Owner: glvd
--

CREATE INDEX deb_cve_search ON public.deb_cve USING btree (dist_id, debsec_vulnerable, deb_source, deb_version);


--
-- Name: deb_cve deb_cve_dist_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: glvd
--

ALTER TABLE ONLY public.deb_cve
    ADD CONSTRAINT deb_cve_dist_id_fkey FOREIGN KEY (dist_id) REFERENCES public.dist_cpe(id);


--
-- Name: debsec_cve debsec_cve_dist_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: glvd
--

ALTER TABLE ONLY public.debsec_cve
    ADD CONSTRAINT debsec_cve_dist_id_fkey FOREIGN KEY (dist_id) REFERENCES public.dist_cpe(id);


--
-- Name: debsrc debsrc_dist_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: glvd
--

ALTER TABLE ONLY public.debsrc
    ADD CONSTRAINT debsrc_dist_id_fkey FOREIGN KEY (dist_id) REFERENCES public.dist_cpe(id);


--
-- PostgreSQL database dump complete
--

