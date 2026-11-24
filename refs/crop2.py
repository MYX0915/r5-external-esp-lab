from PIL import Image
im=Image.open("green_test.png")
im.crop((900,240,1150,420)).resize((750,540), Image.NEAREST).save("crop_green.png")
print("ok")
