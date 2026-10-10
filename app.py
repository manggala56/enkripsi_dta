import streamlit as st
import database
import rsa_engine
import encryption
import decryption

st.set_page_config(page_title="Hybrid E2EE Chat Engine", page_icon="🛡️", layout="wide")

# Inisialisasi Database JSON & Keypair Akun Demo jika belum ada
database.init_db()

for user in ["Alice", "Bob"]:
    if not database.get_user_keys(user):
        with st.spinner(f"Membuat pasangan kunci RSA 512-bit untuk {user}..."):
            pub, priv = rsa_engine.generate_keypair(bits=256)
            database.save_user(user, pub, priv)

alice_keys = database.get_user_keys("Alice")
bob_keys = database.get_user_keys("Bob")

# Sidebar
with st.sidebar:
    st.header("🔑 Manajemen Identitas & Kunci")
    st.write("**Alice Public Modulus ($n$):**")
    st.code(str(alice_keys["public"][1])[:36] + "...", language="text")

    st.write("**Bob Public Modulus ($n$):**")
    st.code(str(bob_keys["public"][1])[:36] + "...", language="text")

    st.divider()
    if st.button("🗑️ Reset Chat & Database JSON"):
        database.clear_db()
        # Regenerasi kunci
        for user in ["Alice", "Bob"]:
            pub, priv = rsa_engine.generate_keypair(bits=256)
            database.save_user(user, pub, priv)
        st.success("Database di-reset!")
        st.rerun()

st.title("🛡️ Hybrid E2EE Encrypted Messenger")
st.caption("Arsitektur Modular: Asimetris RSA (Kunci Sesi) + Simetris ChaCha20 (Pesan Teks) + Persistensi JSON")

col_chat, col_inspect = st.columns([1.2, 1])

# Sisi Kiri: Tampilan Obrolan
with col_chat:
    st.subheader("💬 Antarmuka Chat")
    chat_box = st.container(height=420)
    
    messages = database.get_all_messages()
    with chat_box:
        if not messages:
            st.info("Belum ada riwayat pesan di database.json. Silakan mulai obrolan.")
        for msg in messages:
            sender = msg["sender"]
            receiver = msg["receiver"]
            
            # Dekripsi dinamis berdasarkan kunci privat penerima
            rec_priv = alice_keys["private"] if receiver == "Alice" else bob_keys["private"]
            try:
                decrypted_text = decryption.decrypt_message(msg["payload"], rec_priv)
            except Exception as e:
                decrypted_text = f"[Dekripsi Gagal: {e}]"
            
            with st.chat_message(sender.lower()):
                st.write(f"**{sender}** ➔ **{receiver}**")
                st.write(decrypted_text)

    # Input Form
    with st.form("send_form", clear_on_submit=True):
        c1, c2 = st.columns([1, 3])
        with c1:
            active_sender = st.selectbox("Pengirim:", ["Alice", "Bob"])
        with c2:
            pesan_input = st.text_input("Tulis pesan rahasia:")

        btn_kirim = st.form_submit_button("🔒 Enkripsi & Simpan ke DB")

        if btn_kirim and pesan_input.strip():
            active_receiver = "Bob" if active_sender == "Alice" else "Alice"
            rec_pub = bob_keys["public"] if active_receiver == "Bob" else alice_keys["public"]
            
            # 1. Enkripsi pesan
            payload = encryption.encrypt_message(pesan_input, rec_pub)
            
            # 2. Simpan hanya ciphertext & encrypted key ke database.json
            database.append_message(active_sender, active_receiver, payload)
            
            st.rerun()

# Sisi Kanan: Inspeksi Payload Transmisi (Data di database.json)
with col_inspect:
    st.subheader("📦 Inspeksi Data Jaringan & DB")
    st.caption("File `database.json` hanya menyimpan struktur terenkripsi berikut:")

    if messages:
        latest = messages[-1]
        st.write(f"**Paket Terakhir ({latest['sender']} ➔ {latest['receiver']}):**")
        st.json(latest["payload"])

        with st.expander("🔬 Analisis Keamanan Hybrid", expanded=True):
            st.markdown(f"""
            - **Asymmetric Layer (RSA-512):**
              `enc_session_key` bernilai bilangan integer besar. Hanya pemegang private exponent ($d$) milik penerima yang bisa menghitung $m = c^d \pmod n$ untuk memperoleh 32-byte session key.
            - **Symmetric Layer (ChaCha20):**
              Teks pesan dienkripsi secara stream menggunakan kunci 256-bit dan nonce 96-bit, mencegah serangan statistik frekuensi.
            - **Zero Plaintext Storage:**
              Teks asli sama sekali tidak disimpan di file `database.json`.
            """)
    else:
        st.info("Kirim pesan untuk melihat analisis payload.")