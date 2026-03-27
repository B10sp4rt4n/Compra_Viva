
import json, os, base64
from datetime import datetime
import pandas as pd
import numpy as np
import streamlit as st
import matplotlib.pyplot as plt

from aup_core import (
    evaluate_scenarios, recommend_compensations, make_acta_cierre,
    route_to_elastic, init_db, insert_negociacion, insert_iteracion, insert_cierre,
    load_vertical_rules, recommend_semantic, export_acta_docx,
    chain_hash, sha256_of_text, export_contract_docx,
    generate_rsa_keypair, sign_with_pem, verify_with_pem,
    tsa_generate_token, tsa_verify_token,
    parse_certificate, verify_cert_signature, is_cert_time_valid
)

st.set_page_config(page_title="AUP Compra Viva v6", layout="wide")
st.title("AUP Compra Viva — v6 (TSA demo + X.509)")

DB_PATH = "data/aup_compra.sqlite"; RULES_PATH = "data/vertical_rules.yml"
init_db(DB_PATH); v_rules = load_vertical_rules(RULES_PATH)

# Sidebar global
st.sidebar.header("Parámetros globales")
vertical = st.sidebar.selectbox("Vertical", ["SaaS/MSP","Logistica/FM","Industrial/Procurement"])
T1 = st.sidebar.slider("Umbral T1", 0.10, 0.80, 0.35, 0.01); T2 = st.sidebar.slider("Umbral T2", 0.20, 1.00, 0.60, 0.01)
E_c = st.sidebar.slider("Elasticidad Comprador", 0.10, 1.50, 0.55, 0.01); E_v = st.sidebar.slider("Elasticidad Vendedor", 0.10, 1.50, 0.50, 0.01)
w_precio = st.sidebar.slider("Peso Precio", 0.0, 1.0, 0.45, 0.01); w_plazo  = st.sidebar.slider("Peso Plazo",  0.0, 1.0, 0.20, 0.01); w_alc = st.sidebar.slider("Peso Alcance",0.0, 1.0, 0.20, 0.01); w_riesgo = st.sidebar.slider("Peso Riesgo", 0.0, 1.0, 0.15, 0.01)
suma = max(w_precio+w_plazo+w_alc+w_riesgo, 1e-9); weights = {"precio": w_precio/suma, "plazo": w_plazo/suma, "alcance": w_alc/suma, "riesgo": w_riesgo/suma}
roi_min = st.sidebar.slider("ROI mínimo comprador", 0.00, 0.50, 0.10, 0.01); mar_min = st.sidebar.slider("Margen mínimo vendedor", 0.00, 0.50, 0.15, 0.01)
policies = {"roi_min_c": roi_min, "margen_min_v": mar_min}

st.header("Ingesta de escenarios")
c1, c2, c3 = st.columns([2,2,1])
with c1:
    st.write("Descarga plantilla CSV (precio_rel, plazo_rel, alcance_gap, riesgo)")
    tmpl = pd.DataFrame({"precio_rel":[1.00,0.95,0.90],"plazo_rel":[1.00,1.10,0.90],"alcance_gap":[0.00,0.05,0.10],"riesgo":[0.10,0.18,0.25]})
    st.download_button("Descargar plantilla CSV", data=tmpl.to_csv(index=False).encode("utf-8"), file_name="template_escenarios.csv", mime="text/csv")
with c2:
    up = st.file_uploader("Sube CSV/JSON", type=["csv","json"], accept_multiple_files=False, key="uploader")
    df_raw = None
    if up:
        df_raw = pd.read_csv(up) if up.name.endswith(".csv") else pd.read_json(up)
        st.success(f"Cargados {len(df_raw)} escenarios."); st.dataframe(df_raw.head(20), use_container_width=True)
with c3:
    n = st.number_input("N escenarios IA", 5, 200, 36, 1)
    if st.button("Generar IA"):
        rng = np.random.default_rng(42)
        df_raw = pd.DataFrame({"precio_rel": rng.choice([0.85,0.90,0.95,1.00], size=n),"plazo_rel":  rng.choice([0.90,1.00,1.10], size=n),"alcance_gap":rng.choice([0.00,0.05,0.10], size=n),"riesgo":     rng.choice([0.10,0.18,0.25], size=n)})
        st.session_state["df_generated"] = df_raw; st.success("Escenarios IA generados.")
if 'df_generated' in st.session_state and ('df_raw' not in locals() or df_raw is None): df_raw = st.session_state['df_generated']

st.divider()
tab1, tab2, tab3, tab4, tab5 = st.tabs(["🧪 Simula", "🤝 Negocia", "🧾 Cierre", "🔍 Auditor", "🔐 Certs/TSA"])

with tab1:
    st.subheader("Simulación y sensibilidad")
    if df_raw is None or df_raw.empty: st.info("Carga o genera escenarios para simular.")
    else:
        evaluated = evaluate_scenarios(df=df_raw.copy(), T1=T1, T2=T2, E_c=E_c, E_v=E_v, weights=weights, policies=policies)
        st.dataframe(evaluated, use_container_width=True)
        st.download_button("Descargar evaluados CSV", data=evaluated.to_csv(index=False).encode("utf-8"), file_name="escenarios_evaluados.csv", mime="text/csv")
        st.markdown("**Mapa ROI vs Margen (Pareto)**"); fig1, ax1 = plt.subplots()
        feas = evaluated[evaluated["feasible"]]; non = evaluated[~evaluated["feasible"]]; par = evaluated[evaluated["pareto"]]
        ax1.scatter(non["ROI_c"], non["margen_v"], s=20, label="No factible"); ax1.scatter(feas["ROI_c"], feas["margen_v"], s=40, label="Factible"); ax1.scatter(par["ROI_c"], par["margen_v"], s=70, marker="D", label="Pareto")
        ax1.set_xlabel("ROI comprador"); ax1.set_ylabel("Margen vendedor"); ax1.legend(); st.pyplot(fig1)
        st.markdown("**Presión P**"); fig2, ax2 = plt.subplots(); ax2.plot(range(len(evaluated)), evaluated["P"]); ax2.axhline(T1, linestyle="--"); ax2.axhline(T2, linestyle="--"); ax2.set_xlabel("Escenario"); ax2.set_ylabel("P"); st.pyplot(fig2)

with tab2:
    st.subheader("Negociación paso a paso")
    c0, _ = st.columns([2,3])
    with c0:
        compra_id = st.text_input("Compra ID", f"AUP-PROC-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}")
        comprador = st.text_input("Comprador", "Empresa_X"); vendedor  = st.text_input("Vendedor", "Proveedor_Y")
        if st.button("Iniciar negociación (SQLite)"):
            insert_negociacion(DB_PATH, compra_id, comprador, vendedor, T1, T2, E_c, E_v); st.success("Negociación creada en SQLite."); st.session_state["compra_id"] = compra_id; st.session_state["chain_hash"] = ""
    c1, c2, c3, c4 = st.columns(4)
    with c1: precio_rel = st.number_input("precio_rel", 0.5, 1.5, 0.95, 0.01)
    with c2: plazo_rel = st.number_input("plazo_rel", 0.5, 1.5, 1.05, 0.01)
    with c3: alcance_gap = st.number_input("alcance_gap", 0.0, 1.0, 0.05, 0.01)
    with c4: riesgo = st.number_input("riesgo", 0.0, 1.0, 0.18, 0.01)
    gpre = abs(1.0 - precio_rel); gpla = abs(1.0 - plazo_rel); gaps = {"pre": gpre, "pla": gpla, "alc": alcance_gap}
    E_joint = (E_c + E_v)/2.0; P = (weights["precio"]*gpre + weights["plazo"]*gpla + weights["alcance"]*alcance_gap + weights["riesgo"]*riesgo) / max(E_joint, 1e-6)
    M = (E_c + E_v) - (gpre + gpla + riesgo); zona = "elastica" if P<=T1 else ("fluencia" if P<=T2 else "ruptura")
    m1, m2, m3 = st.columns(3); m1.metric("P (presión)", f"{P:.3f}"); m2.metric("M (colchón)", f"{M:.3f}"); m3.metric("Zona", zona)
    base_recs = recommend_compensations(P, M, zona, gaps); vert_recs = recommend_semantic(v_rules, vertical, gaps)
    st.write("**Recomendaciones IA** (base + vertical):"); 
    for r in base_recs + vert_recs: st.markdown(f"- {r}")
    st.markdown("**Ruta de concesión automática → zona elástica (T1)**")
    if st.button("Calcular ruta mínima"):
        (pr2, pl2, ag2, r2), meta = route_to_elastic(precio_rel, plazo_rel, alcance_gap, riesgo, T1, E_c, E_v, weights)
        st.info(f"Sugerido: precio_rel→{pr2:.2f}, plazo_rel→{pl2:.2f}, alcance_gap→{ag2:.2f}, riesgo→{r2:.2f} | P={meta['P']:.3f}, M={meta['M']:.3f}, Δ={meta['delta_sum']:.3f}")
        st.json(meta["steps"][-5:] if meta["steps"] else [])
    if "neg_log" not in st.session_state: st.session_state["neg_log"] = []
    if st.button("Registrar iteración"):
        it = {"t": datetime.utcnow().isoformat(), "precio_rel": float(precio_rel), "plazo_rel": float(plazo_rel), "alcance_gap": float(alcance_gap), "riesgo": float(riesgo), "P": float(P), "M": float(M), "zona": zona, "acciones": base_recs + vert_recs}
        prev = st.session_state.get("chain_hash",""); curr = chain_hash(prev, it); it["h_prev"] = prev; it["h_curr"] = curr; st.session_state["chain_hash"] = curr
        st.session_state["neg_log"].append(it); 
        if "compra_id" in st.session_state: insert_iteracion(DB_PATH, st.session_state["compra_id"], it)
        st.success("Iteración registrada (local + SQLite, hash encadenado).")
    if st.session_state["neg_log"]:
        st.write("**Bitácora (sesión)**"); st.dataframe(pd.DataFrame(st.session_state["neg_log"]), use_container_width=True)
        st.download_button("Descargar bitácora JSON", data=json.dumps(st.session_state["neg_log"], indent=2).encode("utf-8"), file_name="bitacora_negociacion.json", mime="application/json")

with tab3:
    st.subheader("Acta, firmas (PKI) + TSA y contrato")
    c1, c2 = st.columns(2)
    with c1:
        compra_id = st.text_input("Compra ID (cierre)", st.session_state.get("compra_id", f"AUP-PROC-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"))
        comprador = st.text_input("Comprador", "Empresa_X"); vendedor  = st.text_input("Vendedor", "Proveedor_Y")
    with c2:
        resolucion = st.text_input("Resolución", "Aceptada con compensaciones")
        contrapartidas = st.text_input("Contrapartidas (coma)", "SLA L2, Anticipo 20%")
        evidencias = st.text_input("Evidencias (coma)", "PDF contrato, CFDI, Fotos entrega")
    ctx = {"compra_id": compra_id, "comprador": comprador, "vendedor": vendedor, "T1": T1, "T2": T2, "E_c": E_c, "E_v": E_v}
    iter_log = st.session_state.get("neg_log", [])
    cierre = {"fecha": datetime.utcnow().strftime("%Y-%m-%d %H:%MZ"), "resolucion": resolucion, "contrapartidas": [x.strip() for x in contrapartidas.split(",") if x.strip()], "evidencias": [x.strip() for x in evidencias.split(",") if x.strip()]}
    md, sha = make_acta_cierre(ctx, iter_log, cierre); st.code(md, language="markdown"); st.write(f"SHA256 acta: `{sha}`"); st.write(f"Hash cadena (último): `{st.session_state.get('chain_hash','')}`")
    st.markdown("**Firmas PKI y TSA (demo)**")
    colA, colB, colC = st.columns(3)
    with colA:
        if st.button("Generar par de llaves (demo)"):
            try:
                priv, pub = generate_rsa_keypair()
                st.session_state["pki_private_pem"] = priv; st.session_state["pki_public_pem"] = pub
                st.success("Par RSA generado (demo).")
            except Exception as e:
                st.error(f"No se pudo generar llaves: {e}")
        st.text_area("Private PEM (firma acta)", st.session_state.get("pki_private_pem",""), height=140, key="pem_priv")
    with colB:
        st.text_area("Public PEM (verificación)", st.session_state.get("pki_public_pem",""), height=140, key="pem_pub")
        if st.button("Firmar acta (PKI)"):
            try:
                sig = sign_with_pem(st.session_state.get("pem_priv",""), md)
                st.session_state["acta_sig_b64"] = sig; st.success("Acta firmada (PKI).")
            except Exception as e:
                st.error(f"Error al firmar: {e}")
        st.text_input("Firma Acta (Base64)", st.session_state.get("acta_sig_b64",""), key="sig_b64")
    with colC:
        if st.button("Verificar firma (PKI)"):
            try:
                ok = verify_with_pem(st.session_state.get("pem_pub",""), md, st.session_state.get("sig_b64",""))
                st.success("Firma válida.") if ok else st.error("Firma inválida.")
            except Exception as e:
                st.error(f"Error al verificar: {e}")
        # TSA token
        st.markdown("---")
        if st.button("Generar TSA token (demo)"):
            try:
                imprint = sha256_of_text(md)
                tsa_priv = st.session_state.get("pem_priv","")
                token = tsa_generate_token(tsa_priv, imprint)
                st.session_state["tsa_token"] = token
                st.success("TSA token generado (demo).")
            except Exception as e:
                st.error(f"No se pudo generar TSA token: {e}")
        if st.button("Verificar TSA token (demo)"):
            try:
                token = st.session_state.get("tsa_token",{})
                ok = tsa_verify_token(st.session_state.get("pem_pub",""), token)
                st.success("TSA token válido.") if ok else st.error("TSA token inválido.")
            except Exception as e:
                st.error(f"Error TSA verify: {e}")
    # Export y persistencia
    if st.button("Exportar acta (DOCX)"):
        packed_sigs = {"public_pem": st.session_state.get("pem_pub",""), "signature_b64": st.session_state.get("sig_b64","")}
        tsa = st.session_state.get("tsa_token")
        out_path = f"data/acta_cierre_{compra_id}.docx"; export_acta_docx(out_path, ctx, iter_log, cierre, sha, packed_sigs, packed_sigs, tsa)
        with open(out_path, "rb") as f: st.download_button("Descargar DOCX", data=f.read(), file_name=f"acta_cierre_{compra_id}.docx", mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    if st.button("Guardar cierre en SQLite"):
        packed_sigs = {"public_pem": st.session_state.get("pem_pub",""), "signature_b64": st.session_state.get("sig_b64",""), "tsa_token": st.session_state.get("tsa_token")}
        insert_cierre(DB_PATH, compra_id, cierre["fecha"], resolucion, cierre["contrapartidas"], cierre["evidencias"], sha, packed_sigs, packed_sigs); st.success("Cierre guardado en SQLite (con firmas/TSA si se capturaron).")
    st.divider()
    st.markdown("**Contrato (DOCX)**")
    c3, c4, c5 = st.columns(3)
    with c3:
        precio_total = st.text_input("Precio total", "1000000"); moneda = st.text_input("Moneda", "MXN"); anticipo = st.number_input("Anticipo %", 0, 100, 20, 1)
    with c4:
        vigencia = st.number_input("Vigencia (meses)", 1, 60, 12, 1); SLA = st.text_input("SLA", "L2"); penal = st.text_input("Penalizaciones", "OTIF < 95%: 5% mensual")
    with c5:
        objeto = st.text_area("Objeto", "Prestación de servicios de ciberseguridad gestionados (MSP).")
        alcance = st.text_area("Alcance", "Monitoreo 24/7, EDR, hardening, respuesta ante incidentes.")
    terms = {"precio_total": precio_total, "moneda": moneda, "anticipo_pct": anticipo, "vigencia_meses": vigencia, "SLA": SLA, "penalizaciones": penal, "objeto": objeto, "alcance": alcance}
    if st.button("Exportar contrato (DOCX)"):
        cpath = f"data/contrato_{compra_id}.docx"; export_contract_docx(cpath, ctx, cierre, terms, st.session_state.get("sig_b64"), st.session_state.get("sig_b64"))
        with open(cpath, "rb") as f: st.download_button("Descargar Contrato DOCX", data=f.read(), file_name=f"contrato_{compra_id}.docx", mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document")

with tab4:
    st.subheader("Auditor — Cadena y Firmas")
    st.markdown("Sube una **bitácora JSON** o usa la de sesión. Verifica cadena; valida firma PKI del Acta y token TSA.")
    up_json = st.file_uploader("Bitácora JSON", type=["json"], key="audit_json")
    if st.button("Auditar cadena"):
        try:
            if up_json:
                log = json.loads(up_json.read().decode("utf-8"))
            else:
                log = st.session_state.get("neg_log", [])
            ok_chain = True; prev = ""
            for i, it in enumerate(log):
                recomputed = chain_hash(prev, {k:v for k,v in it.items() if k not in ("h_prev","h_curr")})
                if it.get("h_prev","") != prev or it.get("h_curr","") != recomputed:
                    ok_chain = False; break
                prev = recomputed
            st.success("Cadena íntegra.") if ok_chain else st.error("Cadena ALTERADA o incompleta.")
        except Exception as e:
            st.error(f"Error en auditoría: {e}")
    pem_pub = st.text_area("Public PEM (verificar Acta)", "", height=120)
    sig_b64 = st.text_input("Firma Base64 del Acta", "")
    acta_md_sample = st.text_area("Acta Markdown a verificar (pega contenido)", "", height=140)
    if st.button("Verificar firma del Acta (PKI)"):
        try:
            ok = verify_with_pem(pem_pub, acta_md_sample, sig_b64)
            st.success("Firma válida.") if ok else st.error("Firma inválida.")
        except Exception as e:
            st.error(f"Error al verificar: {e}")
    st.markdown("---")
    tsa_token_json = st.text_area("TSA token (JSON)", "", height=140)
    if st.button("Verificar TSA token"):
        try:
            token = json.loads(tsa_token_json)
            ok = tsa_verify_token(pem_pub, token)
            st.success("TSA token válido.") if ok else st.error("TSA token inválido.")
        except Exception as e:
            st.error(f"Error verificando TSA token: {e}")

with tab5:
    st.subheader("Certificados X.509 — inspección y validación básica")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Certificado de firmante (PEM)**")
        cert_pem = st.text_area("Pega certificado (PEM)", "", height=220, key="cert1")
        if st.button("Parsear cert"):
            info = parse_certificate(cert_pem)
            if info: st.json({k:v for k,v in info.items() if k!='cert_obj'})
            else: st.error("No se pudo parsear el certificado.")
        if st.button("¿Vigente ahora?"):
            st.success("Vigente.") if is_cert_time_valid(cert_pem) else st.error("No vigente.")
    with c2:
        st.markdown("**Certificado emisor (PEM)**")
        issuer_pem = st.text_area("Pega issuer (PEM)", "", height=220, key="cert2")
        if st.button("Verificar firma del certificado con issuer"):
            ok = verify_cert_signature(issuer_pem, cert_pem)
            st.success("Cadena básica OK (issuer firma al cert).") if ok else st.error("Fallo firma de issuer.")
    st.info("Nota: Esta validación es **básica** (sin OCSP/CRL ni AIA). Para producción, integrar un validador con red y políticas formales.")
