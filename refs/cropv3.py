from PIL import Image
im=Image.open("esp_v3.png")
im.crop((990,430,1120,570)).resize((520,560), Image.LANCZOS).save("crop_v3a.png")
im.crop((650,500,780,620)).resize((520,480), Image.LANCZOS).save("crop_v3b.png")
print("ok")
