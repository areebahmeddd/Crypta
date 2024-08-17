rule DetectJPEG {
    meta:
        author = "Shivansh Karan"
        description = "Detects JPEG image files"

    strings:
        $jpeg_magic = { FF D8 FF E0 }
        $jpeg_magic_alt = { FF D8 FF E1 }

    condition:
        $jpeg_magic or $jpeg_magic_alt
}

rule DetectPNG {
    meta:
        author = "Shivansh Karan"
        description = "Detects PNG image files"

    strings:
        $png_magic = { 89 50 4E 47 0D 0A 1A 0A }

    condition:
        $png_magic
}

rule DetectGIF {
    meta:
        author = "Shivansh Karan"
        description = "Detects GIF image files"

    strings:
        $gif_magic = "GIF89a"
        $gif_magic_alt = "GIF87a"

    condition:
        $gif_magic or $gif_magic_alt
}

rule DetectAlteredJPEG {
    meta:
        author = "Shivansh Karan"
        description = "Detects potentially altered JPEG image files"

    strings:
        $jpeg_magic = { FF D8 FF E0 }
        $jpeg_end = { FF D9 }
        $suspicious_segment = { FF DA }

    condition:
        $jpeg_magic and not $jpeg_end and $suspicious_segment
}

rule DetectSuspiciousMetadata {
    meta:
        author = "Shivansh Karan"
        description = "Detects images with suspicious or abnormal metadata"

    strings:
        $exif = "Exif"
        $comment = "Comment"

    condition:
        $exif and $comment
}

rule DetectBMP {
    meta:
        author = "Shivansh Karan"
        description = "Detects BMP image files"

    strings:
        $bmp_magic = { 42 4D }

    condition:
        $bmp_magic
}

rule DetectSteganography {
    meta:
        author = "Shivansh Karan"
        description = "Detects potential steganography in images"

    strings:
        $jpeg_magic = { FF D8 FF E0 }
        $large_file = filesize > 500KB

    condition:
        $jpeg_magic and $large_file
}

rule DetectCorruptedImage {
    meta:
        author = "Shivansh Karan"
        description = "Detects corrupted or malformed image files"

    strings:
        $jpeg_magic = { FF D8 FF E0 }
        $invalid_segment = { FF FF FF FF }

    condition:
        $jpeg_magic and $invalid_segment
}

rule DetectTIFF {
    meta:
        author = "Shivansh Karan"
        description = "Detects TIFF image files"

    strings:
        $tiff_magic_1 = { 49 49 2A 00 }
        $tiff_magic_2 = { 4D 4D 00 2A }

    condition:
        $tiff_magic_1 or $tiff_magic_2
}

rule DetectWebP {
    meta:
        author = "Shivansh Karan"
        description = "Detects WebP image files"

    strings:
        $webp_magic = { 52 49 46 46 ?? ?? ?? ?? 57 45 42 50 }

    condition:
        $webp_magic
}

rule DetectImageWithExecutable {
    meta:
        author = "Shivansh Karan"
        description = "Detects images with embedded executable code"

    strings:
        $pe_header = { 4D 5A }
        $jpeg_magic = { FF D8 FF E0 }
        $png_magic = { 89 50 4E 47 0D 0A 1A 0A }

    condition:
        ($jpeg_magic or $png_magic) and $pe_header
}

rule DetectHighlyCompressedJPEG {
    meta:
        author = "Shivansh Karan"
        description = "Detects highly compressed JPEG images, which might indicate tampering"

    strings:
        $jpeg_magic = { FF D8 FF E0 }
        $high_compression = { FF C0 00 11 08 00 64 00 64 03 01 22 00 02 11 01 03 11 01 }

    condition:
        $jpeg_magic and $high_compression
}

rule DetectSVG {
    meta:
        author = "Shivansh Karan"
        description = "Detects SVG image files"

    strings:
        $svg_magic = "<svg"

    condition:
        $svg_magic
}

rule DetectLargeImageFiles {
    meta:
        author = "Shivansh Karan"
        description = "Detects large image files, which might indicate hidden data or steganography"

    strings:
        $jpeg_magic = { FF D8 FF E0 }
        $png_magic = { 89 50 4E 47 0D 0A 1A 0A }

    condition:
        ($jpeg_magic or $png_magic) and filesize > 2MB
}

rule DetectSuspiciousImageExtensions {
    meta:
        author = "Shivansh Karan"
        description = "Detects images with suspicious or mismatched file extensions"

    strings:
        $jpeg_magic = { FF D8 FF E0 }
        $png_magic = { 89 50 4E 47 0D 0A 1A 0A }
        $gif_magic = "GIF89a"

    condition:
        ($jpeg_magic or $png_magic or $gif_magic) and ext != "jpg" and ext != "png" and ext != "gif"
}
