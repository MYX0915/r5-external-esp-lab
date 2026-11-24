from PIL import Image
im=Image.open("green_loot.png")
im.crop((0,620,700,864)).resize((1400,488), Image.LANCZOS).save("crop_green_loot.png")
print("ok")
