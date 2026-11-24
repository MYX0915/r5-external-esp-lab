from PIL import Image
im=Image.open("loot_test2.png")
im.crop((0,620,700,864)).resize((1400,488), Image.LANCZOS).save("crop_loot.png")
print("ok")
