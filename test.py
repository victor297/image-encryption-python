import streamlit as st
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image
import io
import base64
import time

# Function to encrypt an image yh
def encrypt_image(image, key, mode):
    keySize = 32
    ivSize = AES.block_size if mode == AES.MODE_CBC else 0

    rowOrig, columnOrig, depthOrig = image.shape

    minWidth = (AES.block_size + AES.block_size) // depthOrig + 1
    if columnOrig < minWidth:
        raise ValueError(f'The minimum width of the image must be {minWidth} pixels for encryption!')

    imageOrigBytes = image.tobytes()

    key = key.encode('utf-8')
    if len(key) < keySize:
        key = key.ljust(keySize, b'\0')
    elif len(key) > keySize:
        key = key[:keySize]

    iv = get_random_bytes(ivSize)
    cipher = AES.new(key, AES.MODE_CBC, iv) if mode == AES.MODE_CBC else AES.new(key, AES.MODE_ECB)
    imageOrigBytesPadded = pad(imageOrigBytes, AES.block_size)
    ciphertext = cipher.encrypt(imageOrigBytesPadded)

    paddedSize = len(imageOrigBytesPadded) - len(imageOrigBytes)
    void = columnOrig * depthOrig - ivSize - paddedSize
    ivCiphertextVoid = iv + ciphertext + bytes(void)
    imageEncrypted = np.frombuffer(ivCiphertextVoid, dtype=image.dtype).reshape(rowOrig + 1, columnOrig, depthOrig)

    return imageEncrypted, iv

# Function to decrypt an image
def decrypt_image(imageEncrypted, key, iv, mode):
    rowEncrypted, columnOrig, depthOrig = imageEncrypted.shape 
    rowOrig = rowEncrypted - 1
    encryptedBytes = imageEncrypted.tobytes()
    ivSize = AES.block_size if mode == AES.MODE_CBC else 0
    imageOrigBytesSize = rowOrig * columnOrig * depthOrig
    paddedSize = (imageOrigBytesSize // AES.block_size + 1) * AES.block_size - imageOrigBytesSize
    encrypted = encryptedBytes[ivSize : ivSize + imageOrigBytesSize + paddedSize]

    key = key.encode('utf-8')
    if len(key) < 32:
        key = key.ljust(32, b'\0')
    elif len(key) > 32:
        key = key[:32]

    cipher = AES.new(key, AES.MODE_CBC, iv) if mode == AES.MODE_CBC else AES.new(key, AES.MODE_ECB)
    decryptedImageBytesPadded = cipher.decrypt(encrypted)
    decryptedImageBytes = unpad(decryptedImageBytesPadded, AES.block_size)

    decryptedImage = np.frombuffer(decryptedImageBytes, imageEncrypted.dtype).reshape(rowOrig, columnOrig, depthOrig)

    return decryptedImage

# Function to get image download link
def get_image_download_link(img, filename, text):
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    href = f'<a href="data:file/png;base64,{img_str}" download="{filename}">{text}</a>'
    return href

# Streamlit app
st.subheader("Image Encryption for Secure Internet Transfer")
st.write("Project By Ayanlere saheed 20/47cs/01157")

# Sidebar for options
option = st.sidebar.selectbox("Choose an option", ["Encrypt", "Decrypt"])

mode = AES.MODE_CBC

if option == "Encrypt":
    st.header("Encrypt an Image")
    uploaded_file = st.file_uploader("Choose an image to encrypt...", type="png")

    if uploaded_file is not None:
        image = Image.open(uploaded_file)
        image = np.array(image)
        st.image(image, caption='Uploaded Image', use_column_width=True)

        key = st.text_input("Enter encryption key:", type="password")
        
        if st.button("Encrypt Image"):
            if key:
                try:
                    start_time = time.time()
                    imageEncrypted, iv = encrypt_image(image, key, mode)
                    end_time = time.time()
                    encryption_time = end_time - start_time

                    st.image(imageEncrypted, caption='Encrypted Image', use_column_width=True)
                    st.session_state['imageEncrypted'] = imageEncrypted
                    st.session_state['key'] = key
                    st.session_state['iv'] = iv

                    # Metrics display
                    st.subheader("Encryption Metrics")
                    st.write(f"**Encryption Time:** {encryption_time:.4f} seconds")
                    st.write(f"**Original Image Size:** {image.nbytes / 1024:.2f} KB")
                    st.write(f"**Encrypted Image Size:** {imageEncrypted.nbytes / 1024:.2f} KB")

                    # Histogram of pixel values
                    st.subheader("Pixel Value Histogram")
                    st.write("**Original Image:**")
                    st.bar_chart(np.histogram(image.flatten(), bins=256)[0])
                    st.write("**Encrypted Image:**")
                    st.bar_chart(np.histogram(imageEncrypted.flatten(), bins=256)[0])

                    # Save encrypted image
                    encrypted_image_pil = Image.fromarray(imageEncrypted)
                    buf = io.BytesIO()
                    encrypted_image_pil.save(buf, format="PNG")
                    byte_im = buf.getvalue()

                    st.download_button(
                        label="Download Encrypted Image",
                        data=byte_im,
                        file_name="encrypted_image.png",
                        mime="image/png"
                    )

                    mail_ul="https://mail.google.com/mail/u/0/#inbox?compose=new"
                    WhatsApp="https://api.whatsapp.com/send?text=hi%20i%20want%20to%20send%20you%20a%20an%20image%20now%20and%20the%20code%20to%20open%20it"
                    st.markdown(f"[Share on WhatsApp]({WhatsApp})", unsafe_allow_html=True)
                    st.markdown(f"[Share via Email]({mail_ul})", unsafe_allow_html=True)

                    # Stop running the page after encryption is done
                    st.stop()

                except ValueError as e:
                    st.error(str(e))
            else:
                st.error("Please enter a key for encryption.")

elif option == "Decrypt":
    st.header("Decrypt an Image")
    encrypted_file = st.file_uploader("Choose an encrypted image to decrypt...", type="png")

    if encrypted_file is not None:
        imageEncrypted = Image.open(encrypted_file)
        imageEncrypted = np.array(imageEncrypted)
        st.image(imageEncrypted, caption='Uploaded Encrypted Image', use_column_width=True)

        key = st.text_input("Enter decryption key:", type="password")

        iv = st.session_state.get('iv')
        if st.button("Decrypt Image"):
            if key and iv is not None:
                try:
                    decryptedImage = decrypt_image(imageEncrypted, key, iv, mode)
                    st.image(decryptedImage, caption='Decrypted Image', use_column_width=True)
                except ValueError as e:
                    st.error(str(e))
            else:
                st.error("Please enter the correct key and ensure the encrypted image is correctly uploaded.")
