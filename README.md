# nginx-imgresize

A streaming image resizing filter module for nginx. Currently JPEG-only.

It uses cubic interpolation to produce sharp images and properly scales to avoid
aliasing artifacts.

It accurately preserves all input headers. ICC profiles are not stripped.

It minimizes memory use by streaming its input and output without buffering the
entire image.

It is fast, especially at thumbnailing images.

## Requirements

  * nginx 1.9.11+ (nginx-imgresize is only tested on the new module build system)
  * libjpeg (or libjpeg-turbo)

## Installation

```
$ git clone https://github.com/ender672/nginx-imgresize
$ cd /path/to/nginx
$ ./configure --add-dynamic-module=/path/to/nginx-imgresize
```

## Configuration

The following configuration will scale images from disk.

```
http {
    server {
        listen       8090;

        location ~ ^/(\d+)x(\d+)/(.*)$ {
            alias /path/to/images/$3;
            imgresize $1 $2;
        }
    }
}
```

Then visit this URL in your browser:

http://localhost:8090/456x432/imagefilename.jpg
