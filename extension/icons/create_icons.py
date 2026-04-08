"""
create_icons.py
---------------
Generates PNG icons for the SafeLink AI Chrome extension.
Run from the extension/icons/ directory.

Requirements:
    pip install Pillow

Usage:
    cd extension/icons
    python create_icons.py
"""

from PIL import Image, ImageDraw, ImageFilter
import math
import os

def draw_shield_icon(size: int) -> Image.Image:
    """Draw a purple shield icon with checkmark."""
    scale = size / 128
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Background circle
    pad = int(4 * scale)
    draw.ellipse(
        [pad, pad, size - pad, size - pad],
        fill=(13, 15, 26, 255)
    )

    # Shield gradient simulation (draw layered polygons)
    cx, cy = size // 2, size // 2

    # Shield shape as polygon points
    def shield_pts(scale_factor=1.0):
        w = size * 0.72 * scale_factor
        h = size * 0.82 * scale_factor
        ox = cx - w / 2
        oy = int(size * 0.1)
        pts = [
            (cx, oy),
            (ox + w, oy + h * 0.25),
            (ox + w, oy + h * 0.55),
            (cx, oy + h),
            (ox, oy + h * 0.55),
            (ox, oy + h * 0.25),
        ]
        # Translate to center
        return [(x, y) for x, y in pts]

    # Draw outer shield (darker)
    draw.polygon(shield_pts(1.0), fill=(80, 70, 200, 255))

    # Draw inner shield (gradient effect — lighter)
    draw.polygon(shield_pts(0.85), fill=(99, 102, 241, 255))

    # Draw highlight at top
    draw.polygon(shield_pts(0.70), fill=(120, 115, 250, 255))

    # Checkmark
    lw = max(2, int(3.5 * scale))
    chk_x1 = int(cx - 18 * scale)
    chk_y1 = int(cy + 2 * scale)
    chk_x2 = int(cx - 5 * scale)
    chk_y2 = int(cy + 16 * scale)
    chk_x3 = int(cx + 20 * scale)
    chk_y3 = int(cy - 14 * scale)

    draw.line([(chk_x1, chk_y1), (chk_x2, chk_y2)], fill=(255, 255, 255, 240), width=lw)
    draw.line([(chk_x2, chk_y2), (chk_x3, chk_y3)], fill=(255, 255, 255, 240), width=lw)

    # Subtle glow (soft blur layer behind)
    glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.polygon(shield_pts(0.75), fill=(99, 102, 241, 60))
    glow = glow.filter(ImageFilter.GaussianBlur(radius=int(6 * scale)))

    result = Image.alpha_composite(glow, img)
    return result


def main():
    sizes = [16, 32, 48, 128]
    output_dir = os.path.dirname(os.path.abspath(__file__))

    print("Generating SafeLink AI icons...")
    for size in sizes:
        icon = draw_shield_icon(size)
        filename = os.path.join(output_dir, f"icon{size}.png")
        icon.save(filename, "PNG")
        print(f"  [✓] icon{size}.png  ({size}×{size})")

    print(f"\nAll icons saved to: {output_dir}")


if __name__ == "__main__":
    main()
