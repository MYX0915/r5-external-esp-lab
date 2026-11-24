from PIL import Image
im=Image.open("esp_dummy.png")
im.crop((830,400,950,590)).resize((480,760), Image.LANCZOS).save("crop_esp1.png")
im.crop((570,290,700,410)).resize((520,480), Image.LANCZOS).save("crop_esp2.png")
print("ok")
