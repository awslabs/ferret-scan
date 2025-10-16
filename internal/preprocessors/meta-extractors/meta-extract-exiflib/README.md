# EXIF Metadata Extractor

This library extracts EXIF metadata from image files using Go's standard libraries.

## Features

- Extracts common EXIF metadata from JPEG, TIFF, and other image formats
- Provides detailed camera information (make, model, lens)
- Extracts GPS coordinates and location data
- Retrieves date/time information
- Supports technical image details (exposure, aperture, ISO)

## Supported File Types

- JPEG (.jpg, .jpeg)
- TIFF (.tif, .tiff)
- Other formats with EXIF data

## Usage

```go
import "Go-Metadata/exiflib"

// Extract EXIF metadata from an image file
metadata, err := exiflib.Extract("path/to/image.jpg")
if err != nil {
    // Handle error
}

// Access metadata fields
fmt.Println("Camera:", metadata.CameraMake, metadata.CameraModel)
fmt.Println("Taken on:", metadata.DateTime)
fmt.Println("GPS:", metadata.GPSLatitude, metadata.GPSLongitude)
```

## Metadata Fields

The extractor provides the following metadata fields:

| Field | Description |
|-------|-------------|
| `Filename` | Name of the file |
| `FileSize` | Size of the file in bytes |
| `FileType` | Type of the file (JPEG, TIFF, etc.) |
| `MIMEType` | MIME type of the file |
| `ImageWidth` | Width of the image in pixels |
| `ImageHeight` | Height of the image in pixels |
| `CameraMake` | Manufacturer of the camera |
| `CameraModel` | Model of the camera |
| `LensModel` | Model of the lens used |
| `Software` | Software used to create/edit the image |
| `DateTime` | Date and time when the image was taken |
| `ExposureTime` | Exposure time in seconds |
| `FNumber` | F-number (aperture) |
| `ISOSpeed` | ISO speed rating |
| `FocalLength` | Focal length of the lens in mm |
| `GPSLatitude` | GPS latitude in decimal degrees |
| `GPSLongitude` | GPS longitude in decimal degrees |
| `GPSAltitude` | GPS altitude in meters |

## Implementation Details

The extractor uses Go's `image/jpeg` package to decode JPEG files and extract EXIF data. It parses the EXIF data according to the EXIF specification and provides a structured representation of the metadata.

## Limitations

- Only extracts metadata that is present in the EXIF data
- Some camera-specific or non-standard EXIF tags may not be recognized
- GPS coordinates may not be available for all images
