import streamlit as st
import database
import rsa_engine
import encryption
import decryption

st.set_page_config(
    page_title="P2P Hybrid Cryptosystem",
    layout="wide",
    initial_sidebar_state="collapsed"
)


database.init_db()
for user in ["Alice", "Bob"]:
    if not database.get_user_keys(user):
        pub, priv = rsa_engine.generate_keypair(bits=256)
        database.save_user(user, pub, priv)

alice_keys = database.get_user_keys("Alice")
bob_keys = database.get_user_keys("Bob")
messages = database.get_all_messages()


st.markdown("""
<style>
    /* Styling bubble chat */
    .chat-bubble-sender {
        background-color: #1e3a5f;
        color: #e0f2fe;
        padding: 8px 14px;
        border-radius: 14px 14px 2px 14px;
        margin-bottom: 8px;
        margin-left: 20%;
        text-align: right;
        word-break: break-word;
        border: 1px solid #2563eb44;
    }
    .chat-bubble-receiver {
        background-color: #27272a;
        color: #f4f4f5;
        padding: 8px 14px;
        border-radius: 14px 14px 14px 2px;
        margin-bottom: 8px;
        margin-right: 20%;
        text-align: left;
        word-break: break-word;
        border: 1px solid #3f3f46;
    }
    .chat-meta {
        font-size: 10px;
        color: #a1a1aa;
        margin-bottom: 2px;
    }
    /* Kotak pipeline kriptografi */
    .crypto-step-box {
        background-color: #18181b;
        border: 1px solid #27272a;
        border-left: 4px solid #3b82f6;
        padding: 10px 14px;
        border-radius: 6px;
        margin-bottom: 10px;
        font-family: monospace;
        font-size: 11px;
    }
    .crypto-step-title {
        font-weight: 700;
        color: #60a5fa;
        margin-bottom: 4px;
        text-transform: uppercase;
        font-size: 11px;
    }
    .crypto-val {
        color: #e4e4e7;
        word-break: break-all;
    }
</style>
""", unsafe_allow_html=True)


col_alice, col_center, col_bob = st.columns([1, 1.3, 1])


with col_alice:
    st.markdown("### Client Alice")
    st.caption(f"RSA-256 Public Key ($e=65537, n={str(alice_keys['public'][1])[:10]}...$)")
    
    alice_box = st.container(height=460)
    with alice_box:
        if not messages:
            st.caption("Belum ada riwayat pesan.")
        for msg in messages:
            sender = msg["sender"]
            receiver = msg["receiver"]
            
            if sender == "Alice":
                text = msg.get("plaintext_alice_sent", "[Terkirim]")
                st.markdown(f'<div class="chat-meta" style="text-align:right;">Alice (Anda)</div>'
                            f'<div class="chat-bubble-sender">{text}</div>', unsafe_allow_html=True)
            else:
                try:
                    text = decryption.decrypt_message(msg["payload"], alice_keys["private"])
                except Exception:
                    text = "[Gagal dekripsi]"
                st.markdown(f'<div class="chat-meta">Bob</div>'
                            f'<div class="chat-bubble-receiver">{text}</div>', unsafe_allow_html=True)

    with st.form("alice_form", clear_on_submit=True):
        alice_text = st.text_input("Ketik pesan ke Bob:", label_visibility="collapsed", placeholder="Pesan untuk Bob...", key="input_alice")
        send_alice = st.form_submit_button("Kirim via Jalur Aman", use_container_width=True)
        if send_alice and alice_text.strip():
            payload = encryption.encrypt_message(alice_text, bob_keys["public"])
            db_data = database.load_db()
            db_data["messages"].append({
                "sender": "Alice",
                "receiver": "Bob",
                "plaintext_input": alice_text,
                "payload": payload,
                "plaintext_alice_sent": alice_text
            })
            database.save_db(db_data)
            st.rerun()


with col_center:
    st.markdown("### Cryptographic Pipeline")
    st.caption("Visualisasi alur enkripsi hibrida dan dekripsi end-to-end:")
    
    pipeline_container = st.container(height=525)
    with pipeline_container:
        if messages:
            last = messages[-1]
            p = last["payload"]
            s = last["sender"]
            r = last["receiver"]
            rec_priv = bob_keys["private"] if r == "Bob" else alice_keys["private"]
            
            
            st.markdown(f"**FASE 1: Enkripsi ({s} $\\to$ {r})**")
            
            st.markdown(f"""
            <div class="crypto-step-box">
                <div class="crypto-step-title">1. Plaintext Input</div>
                <div class="crypto-val">"{last.get('plaintext_input', '-')}" ({len(last.get('plaintext_input', '').encode('utf-8'))} bytes)</div>
            </div>
            <div class="crypto-step-box">
                <div class="crypto-step-title">2. ChaCha20 Symmetric Stream Generation</div>
                <div class="crypto-val"><b>Nonce (96-bit):</b> {p['nonce_b64']}</div>
                <div class="crypto-val"><b>Ciphertext Stream (Base64):</b> {p['ciphertext_b64']}</div>
            </div>
            <div class="crypto-step-box">
                <div class="crypto-step-title">3. RSA Asymmetric Key Encapsulation (Target: {r})</div>
                <div class="crypto-val"><b>Encrypted Session Key ($c = k^e \pmod n$):</b><br>{p['enc_session_key'][:45]}...</div>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("---")
            
         
            st.markdown(f"**FASE 2: Dekripsi di Sisi Penerima ({r})**")
            
            try:
                decrypted_result = decryption.decrypt_message(p, rec_priv)
                st.markdown(f"""
                <div class="crypto-step-box" style="border-left-color: #10b981;">
                    <div class="crypto-step-title" style="color: #34d399;">1. RSA Session Key Recovery</div>
                    <div class="crypto-val">Menghitung $k = c^d \pmod n$ menggunakan $d$ milik {r}.<br><b>Status:</b> Kunci sesi 256-bit berhasil dipulihkan.</div>
                </div>
                <div class="crypto-step-box" style="border-left-color: #10b981;">
                    <div class="crypto-step-title" style="color: #34d399;">2. ChaCha20 Stream Inversion</div>
                    <div class="crypto-val">Ciphertext diproses ulang via XOR keystream deterministik.<br><b>Plaintext Terpulihkan:</b> "{decrypted_result}"</div>
                </div>
                """, unsafe_allow_html=True)
            except Exception as err:
                st.error(f"Gagal memproses dekripsi: {err}")
        else:
            st.info("Kirim pesan dari Alice atau Bob untuk menganalisis alur data biner.")


with col_bob:
    st.markdown("### Client Bob")
    st.caption(f"RSA-256 Public Key ($e=65537, n={str(bob_keys['public'][1])[:10]}...$)")
    
    bob_box = st.container(height=460)
    with bob_box:
        if not messages:
            st.caption("Belum ada riwayat pesan.")
        for msg in messages:
            sender = msg["sender"]
            receiver = msg["receiver"]
            
            if sender == "Bob":
                text = msg.get("plaintext_bob_sent", "[Terkirim]")
                st.markdown(f'<div class="chat-meta" style="text-align:right;">Bob (Anda)</div>'
                            f'<div class="chat-bubble-sender">{text}</div>', unsafe_allow_html=True)
            else:
                try:
                    text = decryption.decrypt_message(msg["payload"], bob_keys["private"])
                except Exception:
                    text = "[Gagal dekripsi]"
                st.markdown(f'<div class="chat-meta">Alice</div>'
                            f'<div class="chat-bubble-receiver">{text}</div>', unsafe_allow_html=True)

    with st.form("bob_form", clear_on_submit=True):
        bob_text = st.text_input("Ketik pesan ke Alice:", label_visibility="collapsed", placeholder="Pesan untuk Alice...", key="input_bob")
        send_bob = st.form_submit_button("Kirim via Jalur Aman", use_container_width=True)
        if send_bob and bob_text.strip():
            payload = encryption.encrypt_message(bob_text, alice_keys["public"])
            db_data = database.load_db()
            db_data["messages"].append({
                "sender": "Bob",
                "receiver": "Alice",
                "plaintext_input": bob_text,
                "payload": payload,
                "plaintext_bob_sent": bob_text
            })
            database.save_db(db_data)
            st.rerun()


st.markdown("---")
b_col1, b_col2 = st.columns([4, 1])
with b_col1:
    st.caption("P2P Hybrid Cryptography Demonstration Engine • RSA-256 Key Exchange + ChaCha20 Stream Cipher")
with b_col2:
    if st.button("Reset Database", use_container_width=True):
        database.clear_db()
        for user in ["Alice", "Bob"]:
            pub, priv = rsa_engine.generate_keypair(bits=256)
            database.save_user(user, pub, priv)
        st.rerun()