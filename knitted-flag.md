# Knitted Flag
> I got a bit too excited when I started my newest knitting project and accidentally turned my challenge flag into a knitting pattern.

## First look
We are given a strange text file which appears to be a knitting pattern.

## Challanges
- Find someone who understands knitting patterns
- Realize you can interpret the pattern in binary as 8bit chars

## Solution
We started of by trying to understand how the knitting pattern works. Thankfully one of our team members had some experience with knitting and was able to explain how the pattern has to be interpreted.  
We then started to render the pattern into an image and quickly realized that the first and last 4 rows as well as columns are just padding around the real flag an can be ignored.  
After playing around with the image (flipping, rotating, overlapping, etc.) in hope of finding a hidden message to no avail.  
Then we thought about the pattern itself and realized that the pattern is just a grid of 0s and 1s. We then wrote a small python script to convert the pattern into a binary string and then into ascii.  
After playing around with the order of the pattern and bits (top-down, bottom-up, left-right, right-left, etc.) we finally got the flag.
```py
from PIL import Image, ImageDraw

lines = list(
    map(
        lambda x: x.split(": ")[1].split(),
        [line.strip() for line in open("knittingPattern.txt")][3:-2],
    )
)
COLS = 26
ROWS = 36
BOX_SIZE = 10

img = Image.new("RGB", (COLS * BOX_SIZE, ROWS * BOX_SIZE))
draw = ImageDraw.Draw(img)

lnstr = []
lns = []

for i, line in enumerate(lines):
    lnstr.append("")
    x = 0
    if i % 2 == 0:
        line = line[::-1]
    for stitches in line:
        t, cnt = stitches[0], int(stitches[1:])
        cmp = "K" if i % 2 == 0 else "P"
        color = "black" if (t == cmp) else "white"
        draw.rectangle(
            [x * BOX_SIZE, i * BOX_SIZE, (x + cnt) * BOX_SIZE, (i + 1) * BOX_SIZE],
            fill=color,
        )
        x += cnt
        lnstr[i] += str(int(t == cmp)) * cnt
    lnstr[i] = lnstr[i][4:-4]
    lns.append(chr(int(lnstr[i][:8], 2)) + chr(int(lnstr[i][-8:],2)))

print("".join(lns[::-1]))
img.save("pattern.png")
```
