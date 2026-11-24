from PIL import Image
im=Image.open("aim1.png")
# ????????
c1=im.crop((900,240,1150,420)).resize((750,540), Image.NEAREST)
c1.save("crop_icon.png")
# ????????
c2=im.crop((650,480,1100,580)).resize((900,200), Image.NEAREST)
c2.save("crop_teammate.png")
print("???")
