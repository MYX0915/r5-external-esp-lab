from PIL import Image
im=Image.open("loot_off.png")
im.crop((0,600,760,864)).resize((1520,528), Image.LANCZOS).save("crop_off.png")
print("ok")
