rule DetectJPEG
{
    meta:
        description = "Detects JPEG image files"
        author = "Shivansh Karan"
        date = "2024-08-17"
        
    strings:
        $jpeg_magic = { FF D8 FF E0 }    // JPEG files often start with this sequence
        $jpeg_magic_alt = { FF D8 FF E1 } // Alternative JPEG start sequence
        
    condition:
        $jpeg_magic or $jpeg_magic_alt
}

rule DetectPNG
{
    meta:
        description = "Detects PNG image files"
        author = "Shivansh Karan"
        date = "2024-08-17"
        
    strings:
        $png_magic = { 89 50 4E 47 0D 0A 1A 0A }  // PNG files start with this sequence
        
    condition:
        $png_magic
}

rule DetectGIF
{
    meta:
        description = "Detects GIF image files"
        author = "Shivansh Karan"
        date = "2024-08-17"
        
    strings:
        $gif_magic = "GIF89a"  // GIF files start with this string
        $gif_magic_alt = "GIF87a" // Alternate GIF header
        
    condition:
        $gif_magic or $gif_magic_alt
}

rule DetectAlteredJPEG
{
    meta:
        description = "Detects potentially altered JPEG image files"
        author = "Shivansh Karan"
        date = "2024-08-17"
        
    strings:
        $jpeg_magic = { FF D8 FF E0 }    // Standard JPEG start
        $jpeg_end = { FF D9 }             // JPEG end marker
        $suspicious_segment = { FF DA }   // Start of Scan marker which might be altered
        
    condition:
        $jpeg_magic and not $jpeg_end and $suspicious_segment
}

rule DetectSuspiciousMetadata
{
    meta:
        description = "Detects images with suspicious or abnormal metadata"
        author = "Shivansh Karan"
        date = "2024-08-17"
        
    strings:
        $exif = "Exif"  // Presence of EXIF metadata
        $comment = "Comment"  // Suspicious comment section
        
    condition:
        $exif and $comment
}

rule DetectBMP
{
    meta:
        description = "Detects BMP image files"
        author = "Shivansh Karan"
        date = "2024-08-17"
        
    strings:
        $bmp_magic = { 42 4D }  // BMP files start with "BM"
        
    condition:
        $bmp_magic
}

rule DetectSteganography
{
    meta:
        description = "Detects potential steganography in images"
        author = "Shivansh Karan"
        date = "2024-08-17"
        
    strings:
        $jpeg_magic = { FF D8 FF E0 }
        $large_file = filesize > 500KB  // Example threshold, adjust based on context
        
    condition:
        $jpeg_magic and $large_file
}

rule DetectCorruptedImage
{
    meta:
        description = "Detects corrupted or malformed image files"
        author = "Shivansh Karan"
        date = "2024-08-17"
        
    strings:
        $jpeg_magic = { FF D8 FF E0 }
        $invalid_segment = { FF FF FF FF }  // Example of a possible corrupted segment
        
    condition:
        $jpeg_magic and $invalid_segment
}

rule DetectTIFF
{
    meta:
        description = "Detects TIFF image files"
        author = "Shivansh Karan"
        date = "2024-08-17"
        
    strings:
        $tiff_magic_1 = { 49 49 2A 00 }  // TIFF little-endian
        $tiff_magic_2 = { 4D 4D 00 2A }  // TIFF big-endian
        
    condition:
        $tiff_magic_1 or $tiff_magic_2
}

rule DetectWebP
{
    meta:
        description = "Detects WebP image files"
        author = "Shivansh Karan"
        date = "2024-08-17"
        
    strings:
        $webp_magic = { 52 49 46 46 ?? ?? ?? ?? 57 45 42 50 }  // WebP files start with "RIFF" and "WEBP"
        
    condition:
        $webp_magic
}

rule DetectImageWithExecutable
{
    meta:
        description = "Detects images with embedded executable code"
        author = "Shivansh Karan"
        date = "2024-08-17"
        
    strings:
        $pe_header = { 4D 5A }  // MZ header for PE files (Windows executables)
        $jpeg_magic = { FF D8 FF E0 }  // JPEG start
        $png_magic = { 89 50 4E 47 0D 0A 1A 0A }  // PNG start
        
    condition:
        ($jpeg_magic or $png_magic) and $pe_header
}

rule DetectHighlyCompressedJPEG
{
    meta:
        description = "Detects highly compressed JPEG images, which might indicate tampering"
        author = "Shivansh Karan"
        date = "2024-08-17"
        
    strings:
        $jpeg_magic = { FF D8 FF E0 }
        $high_compression = { FF C0 00 11 08 00 64 00 64 03 01 22 00 02 11 01 03 11 01 }  // Example of a high compression marker
        
    condition:
        $jpeg_magic and $high_compression
}

rule DetectSVG
{
    meta:
        description = "Detects SVG image files"
        author = "Shivansh Karan"
        date = "2024-08-17"
        
    strings:
        $svg_magic = "<svg"  // SVG files start with "<svg"
        
    condition:
        $svg_magic
}

rule DetectLargeImageFiles
{
    meta:
        description = "Detects large image files, which might indicate hidden data or steganography"
        author = "Shivansh Karan"
        date = "2024-08-17"
        
    strings:
        $jpeg_magic = { FF D8 FF E0 }
        $png_magic = { 89 50 4E 47 0D 0A 1A 0A }
        
    condition:
        ($jpeg_magic or $png_magic) and filesize > 2MB  // Adjust size threshold as needed
}

rule DetectSuspiciousImageExtensions
{
    meta:
        description = "Detects images with suspicious or mismatched file extensions"
        author = "Shivansh Karan"
        date = "2024-08-17"
        
    strings:
        $jpeg_magic = { FF D8 FF E0 }
        $png_magic = { 89 50 4E 47 0D 0A 1A 0A }
        $gif_magic = "GIF89a"
        
    condition:
        ($jpeg_magic or $png_magic or $gif_magic) and ext != "jpg" and ext != "png" and ext != "gif"
}
