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


with st.sidebar:
    st.subheader("Kontrol Sistem")
    if st.button("Reset Database"):
        database.clear_db()
        for user in ["Alice", "Bob"]:
            pub, priv = rsa_engine.generate_keypair(bits=256)
            database.save_user(user, pub, priv)
        st.rerun()

col_alice, col_network, col_bob = st.columns([1, 1.2, 1])
messages = database.get_all_messages()


with col_alice:
    st.subheader("Klien Alice")
    alice_box = st.container(height=420)
    
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

            align = "Pengirim (Anda)" if sender == "Alice" else "Bob"
            st.markdown(f"**{align}:** {text_display}")

    with st.form("alice_form", clear_on_submit=True):
        alice_text = st.text_input("Pesan ke Bob:", key="input_alice")
        submit_alice = st.form_submit_button("Kirim ke Bob")
        if submit_alice and alice_text.strip():
            # Alice enkripsi pakai public key Bob
            payload = encryption.encrypt_message(alice_text, bob_keys["public"])

            msg_record = {
                "sender": "Alice",
                "receiver": "Bob",
                "payload": payload,
                "plaintext_alice_sent": alice_text
            }
            db_data = database.load_db()
            db_data["messages"].append(msg_record)
            database.save_db(db_data)
            st.rerun()


with col_network:
    st.subheader("Lalu Lintas Jaringan / Payload")
    st.caption("Representasi data mentah yang melintas antar simpul:")
    
    network_box = st.container(height=500)
    with network_box:
        if messages:
            for idx, msg in enumerate(reversed(messages)):
                st.text(f"Paket #{len(messages) - idx}: {msg['sender']} -> {msg['receiver']}")
                st.json(msg["payload"])
                st.markdown("---")
        else:
            st.caption("Menunggu transmisi data...")

with col_bob:
    st.subheader("Klien Bob")
    bob_box = st.container(height=420)
    
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

            align = "Pengirim (Anda)" if sender == "Bob" else "Alice"
            st.markdown(f"**{align}:** {text_display}")

    with st.form("bob_form", clear_on_submit=True):
        bob_text = st.text_input("Pesan ke Alice:", key="input_bob")
        submit_bob = st.form_submit_button("Kirim ke Alice")
        if submit_bob and bob_text.strip():
            # Bob enkripsi pakai public key Alice
            payload = encryption.encrypt_message(bob_text, alice_keys["public"])
            
   
            msg_record = {
                "sender": "Bob",
                "receiver": "Alice",
                "payload": payload,
                "plaintext_bob_sent": bob_text
            }
            db_data = database.load_db()
            db_data["messages"].append(msg_record)
            database.save_db(db_data)
            st.rerun()