from PIL import Image
im=Image.open("back50.png")
im.crop((900,240,1150,420)).resize((750,540), Image.NEAREST).save("crop_back50.png")
print("ok")
