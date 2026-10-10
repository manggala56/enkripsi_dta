import streamlit as st
import database
import rsa_engine
import encryption
import decryption

st.set_page_config(page_title="P2P Encrypted Messaging", layout="wide")

database.init_db()


for user in ["Alice", "Bob"]:
    if not database.get_user_keys(user):
        pub, priv = rsa_engine.generate_keypair(bits=256)
        database.save_user(user, pub, priv)

alice_keys = database.get_user_keys("Alice")
bob_keys = database.get_user_keys("Bob")

col_alice, col_center, col_bob = st.columns([1, 1.2, 1])
messages = database.get_all_messages()

with col_alice:
    st.subheader("Klien Alice")
    alice_box = st.container(height=480)
    
    with alice_box:
        if not messages:
            st.caption("Belum ada pesan.")
        for msg in messages:
            sender = msg["sender"]
            receiver = msg["receiver"]
            
            if receiver == "Alice":
                try:
                    text_display = decryption.decrypt_message(msg["payload"], alice_keys["private"])
                except Exception:
                    text_display = "[Gagal dekripsi]"
            else:
                text_display = msg.get("plaintext_alice_sent", "[Pesan terkirim]")

            label = "Pengirim (Anda)" if sender == "Alice" else "Bob"
            st.markdown(f"**{label}:** {text_display}")

    with st.form("alice_form", clear_on_submit=True):
        alice_text = st.text_input("Pesan ke Bob:", key="input_alice")
        submit_alice = st.form_submit_button("Kirim ke Bob")
        if submit_alice and alice_text.strip():
            payload = encryption.encrypt_message(alice_text, bob_keys["public"])
            msg_record = {
                "sender": "Alice",
                "receiver": "Bob",
                "plaintext_input": alice_text,
                "payload": payload,
                "plaintext_alice_sent": alice_text
            }
            db_data = database.load_db()
            db_data["messages"].append(msg_record)
            database.save_db(db_data)
            st.rerun()


with col_center:
    st.subheader("Pipeline Kriptografi")
    
    if messages:
        latest = messages[-1]
        sender = latest["sender"]
        receiver = latest["receiver"]
        payload = latest["payload"]

        # Bagian Atas: Proses Enkripsi
        st.markdown(f"**Proses Enkripsi ({sender} -> {receiver})**")
        enc_box = st.container(height=230)
        with enc_box:
            st.text(f"Plaintext Input : {latest.get('plaintext_input', '-')}")
            st.text(f"Public Key Penerima (e, n) :")
            pub_target = bob_keys["public"] if receiver == "Bob" else alice_keys["public"]
            st.code(f"e: {pub_target[0]}\nn: {str(pub_target[1])[:32]}...", language="text")
            st.text("Payload Hasil Enkripsi (JSON):")
            st.json(payload)

        st.markdown("---")

        # Proses Dekripsi
        st.markdown(f"**Proses Dekripsi (Sisi {receiver})**")
        dec_box = st.container(height=230)
        with dec_box:
            priv_target = bob_keys["private"] if receiver == "Bob" else alice_keys["private"]
            st.text(f"Private Key Penerima (d, n) :")
            st.code(f"d: {str(priv_target[0])[:32]}...\nn: {str(priv_target[1])[:32]}...", language="text")
            
            try:
                decrypted_res = decryption.decrypt_message(payload, priv_target)
                st.text(f"Ekstraksi Session Key ChaCha20 : Berhasil via RSA")
                st.text(f"Hasil Dekripsi Stream ChaCha20 :")
                st.success(decrypted_res)
            except Exception as e:
                st.error(f"Gagal Dekripsi: {e}")
    else:
        st.caption("Menunggu data dikirim untuk memproses visualisasi enkripsi dan dekripsi...")


with col_bob:
    st.subheader("Klien Bob")
    bob_box = st.container(height=480)
    
    with bob_box:
        if not messages:
            st.caption("Belum ada pesan.")
        for msg in messages:
            sender = msg["sender"]
            receiver = msg["receiver"]
            
            if receiver == "Bob":
                try:
                    text_display = decryption.decrypt_message(msg["payload"], bob_keys["private"])
                except Exception:
                    text_display = "[Gagal dekripsi]"
            else:
                text_display = msg.get("plaintext_bob_sent", "[Pesan terkirim]")

            label = "Pengirim (Anda)" if sender == "Bob" else "Alice"
            st.markdown(f"**{label}:** {text_display}")

    with st.form("bob_form", clear_on_submit=True):
        bob_text = st.text_input("Pesan ke Alice:", key="input_bob")
        submit_bob = st.form_submit_button("Kirim ke Alice")
        if submit_bob and bob_text.strip():
            payload = encryption.encrypt_message(bob_text, alice_keys["public"])
            msg_record = {
                "sender": "Bob",
                "receiver": "Alice",
                "plaintext_input": bob_text,
                "payload": payload,
                "plaintext_bob_sent": bob_text
            }
            db_data = database.load_db()
            db_data["messages"].append(msg_record)
            database.save_db(db_data)
            st.rerun()

st.markdown("---")
if st.button("Reset Database"):
    database.clear_db()
    for user in ["Alice", "Bob"]:
        pub, priv = rsa_engine.generate_keypair(bits=256)
        database.save_user(user, pub, priv)
    st.rerun()