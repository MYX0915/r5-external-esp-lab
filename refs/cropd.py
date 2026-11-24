from PIL import Image
im=Image.open("dummy_glow.png")
im.crop((620,500,820,620)).resize((800,480), Image.LANCZOS).save("crop_dummy.png")
print("ok")
