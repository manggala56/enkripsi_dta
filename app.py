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
    .chat-bubble-sender {
        background-color: #1e3a5f;
        color: #e0f2fe;
        padding: 8px 12px;
        border-radius: 12px 12px 2px 12px;
        margin-bottom: 6px;
        margin-left: 15%;
        text-align: right;
        word-break: break-word;
        border: 1px solid #2563eb33;
    }
    .chat-bubble-receiver {
        background-color: #27272a;
        color: #f4f4f5;
        padding: 8px 12px;
        border-radius: 12px 12px 12px 2px;
        margin-bottom: 6px;
        margin-right: 15%;
        text-align: left;
        word-break: break-word;
        border: 1px solid #3f3f46;
    }
    .chat-label {
        font-size: 11px;
        color: #94a3b8;
        margin-bottom: 2px;
    }
    .flow-card {
        background-color: #18181b;
        border: 1px solid #27272a;
        border-radius: 8px;
        padding: 10px 12px;
        margin-bottom: 8px;
    }
    .flow-card-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 4px;
    }
    .flow-tag {
        font-size: 10px;
        font-weight: 600;
        padding: 2px 6px;
        border-radius: 4px;
        text-transform: uppercase;
    }
    .tag-enc { background-color: #1e3a8a; color: #93c5fd; }
    .tag-pack { background-color: #3730a3; color: #c7d2fe; }
    .tag-dec { background-color: #065f46; color: #a7f3d0; }
    .flow-title { font-weight: 600; font-size: 12px; color: #f1f5f9; }
    .flow-desc { font-size: 11px; color: #94a3b8; margin-bottom: 6px; }
    .flow-data {
        background-color: #09090b;
        border-radius: 4px;
        padding: 6px 8px;
        font-family: monospace;
        font-size: 11px;
        color: #38bdf8;
        word-break: break-all;
    }
    .arrow-divider {
        text-align: center;
        color: #64748b;
        font-size: 12px;
        margin: -4px 0 4px 0;
    }
</style>
""", unsafe_allow_html=True)

col_alice, col_center, col_bob = st.columns([1, 1.4, 1])


with col_alice:
    st.subheader("Alice")
    alice_box = st.container(height=470)
    with alice_box:
        if not messages:
            st.caption("Belum ada percakapan.")
        for msg in messages:
            sender = msg["sender"]
            if sender == "Alice":
                text = msg.get("plaintext_alice_sent", "[Terkirim]")
                st.markdown(f'<div class="chat-label" style="text-align:right;">Anda</div>'
                            f'<div class="chat-bubble-sender">{text}</div>', unsafe_allow_html=True)
            else:
                try:
                    text = decryption.decrypt_message(msg["payload"], alice_keys["private"])
                except Exception:
                    text = "[Gagal dekripsi]"
                st.markdown(f'<div class="chat-label">Bob</div>'
                            f'<div class="chat-bubble-receiver">{text}</div>', unsafe_allow_html=True)

    with st.form("alice_form", clear_on_submit=True):
        alice_text = st.text_input("Pesan ke Bob:", label_visibility="collapsed", placeholder="Ketik pesan untuk Bob...", key="input_alice")
        send_alice = st.form_submit_button("Kirim ke Bob", use_container_width=True)
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
    st.subheader("Alur Enkripsi & Dekripsi")
    flow_container = st.container(height=535)
    
    with flow_container:
        if messages:
            last = messages[-1]
            p = last["payload"]
            s = last["sender"]
            r = last["receiver"]
            rec_priv = bob_keys["private"] if r == "Bob" else alice_keys["private"]

            
            st.markdown(f"""
            <div class="flow-card">
                <div class="flow-card-header">
                    <span class="flow-title">1. Pengacakan Pesan (ChaCha20)</span>
                    <span class="flow-tag tag-enc">Simetris</span>
                </div>
                <div class="flow-desc">Pesan asli diacak menggunakan kunci sesi acak 256-bit agar sangat cepat dan aman.</div>
                <div class="flow-data">
                    Input: "{last.get('plaintext_input', '-')}"<br>
                    Ciphertext: {p['ciphertext_b64']}
                </div>
            </div>
            <div class="arrow-divider">▼</div>
            """, unsafe_allow_html=True)

    
            st.markdown(f"""
            <div class="flow-card">
                <div class="flow-card-header">
                    <span class="flow-title">2. Penguncian Kunci Sesi (RSA)</span>
                    <span class="flow-tag tag-enc">Asimetris</span>
                </div>
                <div class="flow-desc">Kunci ChaCha20 digembok memakai Public Key milik {r}. Hanya {r} yang bisa membukanya.</div>
                <div class="flow-data">
                    Encrypted Key: {p['enc_session_key'][:40]}...
                </div>
            </div>
            <div class="arrow-divider">▼</div>
            """, unsafe_allow_html=True)

            
            st.markdown(f"""
            <div class="flow-card">
                <div class="flow-card-header">
                    <span class="flow-title">3. Paket Data Terkirim (Database / Jaringan)</span>
                    <span class="flow-tag tag-pack">Terenkripsi Total</span>
                </div>
                <div class="flow-desc">Server/penyadap hanya melihat teks acak tanpa tahu isi pesan aslinya.</div>
                <div class="flow-data">
                    Status: Aman (Zero-Plaintext Expose)
                </div>
            </div>
            <div class="arrow-divider">▼</div>
            """, unsafe_allow_html=True)

   
            try:
                decrypted_res = decryption.decrypt_message(p, rec_priv)
                st.markdown(f"""
                <div class="flow-card" style="border-left: 3px solid #10b981;">
                    <div class="flow-card-header">
                        <span class="flow-title">4. Penerima Membuka Pesan ({r})</span>
                        <span class="flow-tag tag-dec">Selesai</span>
                    </div>
                    <div class="flow-desc">{r} memakai Private Key miliknya untuk membuka kunci ChaCha20, lalu membaca teks aslinya.</div>
                    <div class="flow-data" style="color: #4ade80;">
                        Hasil Terbaca: "{decrypted_res}"
                    </div>
                </div>
                """, unsafe_allow_html=True)
            except Exception as e:
                st.error(f"Gagal memulihkan pesan: {e}")
        else:
            st.caption("Kirim pesan dari sisi Alice atau Bob untuk melihat alur transformasi data.")

with col_bob:
    st.subheader("Bob")
    bob_box = st.container(height=470)
    with bob_box:
        if not messages:
            st.caption("Belum ada percakapan.")
        for msg in messages:
            sender = msg["sender"]
            if sender == "Bob":
                text = msg.get("plaintext_bob_sent", "[Terkirim]")
                st.markdown(f'<div class="chat-label" style="text-align:right;">Anda</div>'
                            f'<div class="chat-bubble-sender">{text}</div>', unsafe_allow_html=True)
            else:
                try:
                    text = decryption.decrypt_message(msg["payload"], bob_keys["private"])
                except Exception:
                    text = "[Gagal dekripsi]"
                st.markdown(f'<div class="chat-label">Alice</div>'
                            f'<div class="chat-bubble-receiver">{text}</div>', unsafe_allow_html=True)

    with st.form("bob_form", clear_on_submit=True):
        bob_text = st.text_input("Pesan ke Alice:", label_visibility="collapsed", placeholder="Ketik pesan untuk Alice...", key="input_bob")
        send_bob = st.form_submit_button("Kirim ke Alice", use_container_width=True)
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
b1, b2 = st.columns([4, 1])
with b1:
    st.caption("Protokol Hybrid Cryptography: ChaCha20 (Payload Stream) + RSA-256 (Pertukaran Kunci)")
with b2:
    if st.button("Hapus Riwayat Chat", use_container_width=True):
        database.clear_db()
        for user in ["Alice", "Bob"]:
            pub, priv = rsa_engine.generate_keypair(bits=256)
            database.save_user(user, pub, priv)
        st.rerun()