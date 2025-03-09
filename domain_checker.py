import streamlit as st
import dns.resolver
import pandas as pd
import plotly.express as px
from io import BytesIO, StringIO
import plotly.graph_objects as go
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from datetime import datetime

# Database provider aggiornata
PROVIDERS = {
    'mx': {
        'google.com': 'Google Workspace',
        'aspmx.l.google.com': 'Google Workspace',
        'outlook.com': 'Microsoft 365',
        'protection.outlook.com': 'Microsoft 365',
        'mail.protection.outlook.com': 'Microsoft Exchange Online Protection',
        'amazonses.com': 'Amazon SES',
        'sendgrid.net': 'SendGrid',
        'zoho.com': 'Zoho Mail',
        'yandex.ru': 'Yandex.Mail',
        'mx.cloudflare.net': 'Cloudflare Email Routing',
        'mailgun.org': 'Mailgun'
    },
    'spf': {
        '_spf.google.com': 'Google Workspace',
        'spf.protection.outlook.com': 'Microsoft 365',
        'amazonses.com': 'Amazon SES',
        'sendgrid.net': 'SendGrid',
        'zoho.com': 'Zoho Mail'
    },
    'dmarc': {
        'dmarc.google.com': 'Google Workspace',
        'dmarc.protection.outlook.com': 'Microsoft 365',
        'amazon.com': 'Amazon SES'
    }
}

# Domini disposable noti
DISPOSABLE_DOMAINS = {
    '10minutemail.com', 'temp-mail.org', 'yopmail.com', 
    'mailinator.com', 'guerrillamail.com', 'dispostable.com'
}

def get_mx_records(domain):
    try:
        records = dns.resolver.resolve(domain, 'MX')
        return [str(r.exchange).lower() for r in records]
    except Exception as e:
        return f"Errore: {str(e)}"

def get_txt_records(domain, record_type='TXT'):
    try:
        records = dns.resolver.resolve(domain, 'TXT')
        return [str(r) for r in records 
                if record_type.lower() in str(r).lower()]
    except Exception as e:
        return f"Errore: {str(e)}"

def check_dmarc(domain):
    return get_txt_records(f'_dmarc.{domain}')

def detect_provider(domain):
    results = {
        'MX': [],
        'SPF': [],
        'DMARC': [],
        'Disposable': False
    }
    
    # Controllo MX
    mx_records = get_mx_records(domain)
    if isinstance(mx_records, list):
        for mx in mx_records:
            for provider_mx, name in PROVIDERS['mx'].items():
                if provider_mx in mx:
                    results['MX'].append(name)
    else:
        results['MX'] = mx_records
    
    # Controllo SPF
    spf_records = get_txt_records(domain, 'SPF')
    if spf_records and not isinstance(spf_records, str):
        for spf in spf_records:
            for provider_spf, name in PROVIDERS['spf'].items():
                if provider_spf in spf:
                    results['SPF'].append(name)
    else:
        results['SPF'] = spf_records
    
    # Controllo DMARC
    dmarc_records = check_dmarc(domain)
    if dmarc_records and not isinstance(dmarc_records, str):
        for dmarc in dmarc_records:
            for provider_dmarc, name in PROVIDERS['dmarc'].items():
                if provider_dmarc in dmarc:
                    results['DMARC'].append(name)
    else:
        results['DMARC'] = dmarc_records
    
    # Controllo disposable
    if domain in DISPOSABLE_DOMAINS:
        results['Disposable'] = True
    
    return results

def process_domain(domain):
    domain = domain.strip().lstrip('@')
    detection = detect_provider(domain)
    
    return {
        'Dominio': f"@{domain}",
        'MX Records': ', '.join(detection['MX']) if isinstance(detection['MX'], list) else detection['MX'],
        'SPF Records': ', '.join(detection['SPF']) if isinstance(detection['SPF'], list) else detection['SPF'],
        'DMARC Records': ', '.join(detection['DMARC']) if isinstance(detection['DMARC'], list) else detection['DMARC'],
        'Provider Rilevato': ' | '.join(set(detection['MX'] + detection['SPF'] + detection['DMARC'])) 
                              if all(isinstance(x, list) for x in [detection['MX'], detection['SPF'], detection['DMARC']]) 
                              else 'Non determinabile',
        'Email Temporanea': 'Sì' if detection['Disposable'] else 'No'
    }

def generate_pdf(df):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    p.drawString(40, height-50, f"Report Analisi Email Provider - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    y = height - 100
    for _, row in df.iterrows():
        p.drawString(40, y, f"Istituzione: {row.get('Istituzione', 'N/A')}")
        y -= 20
        p.drawString(40, y, f"Ente: {row.get('Ente', 'N/A')}")
        y -= 20
        p.drawString(40, y, f"Dominio: {row['Dominio']}")
        y -= 20
        p.drawString(40, y, f"Provider Rilevato: {row['Provider Rilevato']}")
        y -= 20
        p.drawString(40, y, f"Email Temporanea: {row['Email Temporanea']}")
        y -= 20
        p.drawString(40, y, "Record MX:")
        y -= 15
        p.drawString(60, y, row['MX Records'])
        y -= 20
        p.drawString(40, y, "Record SPF:")
        y -= 15
        p.drawString(60, y, row['SPF Records'])
        y -= 20
        p.drawString(40, y, "Record DMARC:")
        y -= 15
        p.drawString(60, y, row['DMARC Records'])
        y -= 40
        
        if y < 100:
            p.showPage()
            y = height - 50

    p.save()
    buffer.seek(0)
    return buffer

# Layout pagina
st.set_page_config(page_title="Email Domain Analyzer", layout="wide")
st.title('🔍 Email Domain Intelligence Analyzer')

# Sidebar
with st.sidebar:
    st.header('Opzioni di Analisi')
    include_errors = st.checkbox('Includi errori DNS nel report', value=True)
    export_format = st.selectbox('Formato di esportazione', 
                                 ['CSV', 'Excel', 'JSON', 'PDF'])
    st.markdown('---')
    st.write("ℹ️ I grafici sono interattivi e stampabili")

# Pulsante di stampa
st.markdown(
    """
    <style>
    @media print {
        .main { max-width: 100% !important; }
        .sidebar { display: none; }
        .stButton { display: none; }
    }
    </style>
    """,
    unsafe_allow_html=True
)
st.button('🖨️ Stampa Report', on_click=lambda: st.markdown('window.print();', unsafe_allow_html=True))

# Input selezione
option = st.radio("Seleziona input", ("Singolo dominio", "Lista domini"), horizontal=True)

if option == "Singolo dominio":
    domain = st.text_input("Inserisci il dominio (es. istruzione.it)")
    istituzione = st.text_input("Nome istituzione (opzionale)", "")
    ente = st.text_input("Tipo ente (opzionale)", "")
    
    if domain:  # Rimossa la dipendenza dagli altri campi
        with st.spinner('Analisi avanzata in corso...'):
            result = process_domain(domain)
            result['Istituzione'] = istituzione if istituzione else "N/A"
            result['Ente'] = ente if ente else "N/A"
            
            # Creazione report visivo
            st.subheader('📝 Report Dettagliato')
            col1, col2 = st.columns([2,1])
            
            with col1:
                st.write(f"**Istituzione:** {result['Istituzione']}")
                st.write(f"**Ente:** {result['Ente']}")
                st.write(f"**Dominio:** {result['Dominio']}")
                st.write(f"**Provider Rilevato:** {result['Provider Rilevato']}")
                st.write(f"**Email Temporanea:** {result['Email Temporanea']}")
                
                st.write("### 📊 Record DNS Analizzati")
                st.write(f"**MX Records:** {result['MX Records']}")
                st.write(f"**SPF Records:** {result['SPF Records']}")
                st.write(f"**DMARC Records:** {result['DMARC Records']}")

            with col2:
                # Grafico provider
                providers = result['Provider Rilevato'].split(' | ')
                fig = px.pie(names=providers, title='Provider Detection')
                st.plotly_chart(fig, use_container_width=True)
                
                # Indicatore email temporanea
                fig = go.Figure(go.Indicator(
                    mode = "gauge+number",
                    value = 1 if result['Email Temporanea'] == 'Sì' else 0,
                    title = {'text': "Email Temporanea"},
                    gauge = {
                        'axis': {'range': [0, 1]},
                        'bar': {'color': "red" if result['Email Temporanea'] == 'Sì' else "green"},
                        'steps': [
                            {'range': [0, 0.5], 'color': "green"},
                            {'range': [0.5, 1], 'color': "red"}
                        ],
                        'threshold': {
                            'line': {'color': "black", 'width': 4},
                            'thickness': 0.75,
                            'value': 0.5
                        }
                    }
                ))
                st.plotly_chart(fig, use_container_width=True)

else:
    uploaded_file = st.file_uploader("Carica un file CSV con le seguenti colonne: Istituzione, Dominio, Ente")
    if uploaded_file:
        try:
            # Aggiunto stripping degli spazi nei nomi delle colonne
            df_input = pd.read_csv(uploaded_file)
            df_input.columns = df_input.columns.str.strip()  # Rimuove spazi nelle intestazioni
            
            required_cols = ['Istituzione', 'Dominio', 'Ente']
            if not all(col in df_input.columns for col in required_cols):
                st.error(f"Il file deve contenere le colonne: {', '.join(required_cols)}")
                st.stop()
                
            domains = df_input['Dominio'].astype(str).tolist()
            
            results = []
            with st.spinner(f'Analisi avanzata di {len(domains)} domini...'):
                for _, row in df_input.iterrows():
                    processed = process_domain(row['Dominio'])
                    processed['Istituzione'] = row['Istituzione']
                    processed['Ente'] = row['Ente']
                    if include_errors or 'Errore' not in processed['MX Records']:
                        results.append(processed)
            
            df = pd.DataFrame(results)
            
            # Creazione report visivo
            st.subheader('📊 Report Aggregato')
            col1, col2 = st.columns([2,1])
            
            with col1:
                st.write("### 📋 Risultati Completi")
                st.dataframe(df)
                
                # Grafico provider per ente
                fig = px.sunburst(
                    df,
                    path=['Ente', 'Provider Rilevato'],
                    title='Distribuzione Provider per Tipo Ente',
                    width=600,
                    height=600
                )
                st.plotly_chart(fig, use_container_width=True)
                
            with col2:
                # Grafico email temporanee per ente
                disposable_counts = df.groupby(['Ente', 'Email Temporanea']).size().reset_index(name='Count')
                fig = px.bar(
                    disposable_counts,
                    x='Ente',
                    y='Count',
                    color='Email Temporanea',
                    title='Email Temporanee per Ente'
                )
                st.plotly_chart(fig, use_container_width=True)
                
                # Statistiche
                st.metric("Domini analizzati", len(df))
                st.metric("Domini con errori", len([r for r in results if 'Errore' in r['MX Records']]))
            
            # Esportazione
            st.subheader('💾 Esportazione Dati')
            if export_format == 'CSV':
                csv = df.to_csv(index=False)
                st.download_button(
                    label="Scarica CSV",
                    data=csv,
                    file_name='email_analysis.csv',
                    mime='text/csv'
                )
            elif export_format == 'Excel':
                excel_buffer = BytesIO()
                df.to_excel(excel_buffer, index=False)
                st.download_button(
                    label="Scarica Excel",
                    data=excel_buffer.getvalue(),
                    file_name='email_analysis.xlsx',
                    mime='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                )
            elif export_format == 'JSON':
                json_data = df.to_json(orient='records', force_ascii=False)
                st.download_button(
                    label="Scarica JSON",
                    data=json_data,
                    file_name='email_analysis.json',
                    mime='application/json'
                )
            elif export_format == 'PDF':
                pdf = generate_pdf(df)
                st.download_button(
                    label="Scarica PDF",
                    data=pdf,
                    file_name='email_analysis.pdf',
                    mime='application/pdf'
                )
                
        except Exception as e:
            st.error(f"Errore nel caricamento del file: {str(e)}")