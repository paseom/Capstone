# Base image PHP + Apache
FROM php:8.1-apache

# Install dependency system
RUN apt-get update && apt-get install -y \
    libpng-dev \
    libjpeg-dev \
    libzip-dev \
    unzip \
    curl \
    && docker-php-ext-install pdo pdo_mysql gd zip \
    && rm -rf /var/lib/apt/lists/*

# Download OJS
RUN curl -L https://pkp.sfu.ca/ojs/download/ojs-3.3.0-15.tar.gz -o /tmp/ojs.tar.gz \
    && tar -xzf /tmp/ojs.tar.gz -C /var/www/html --strip-components=1 \
    && rm /tmp/ojs.tar.gz

# Set permission
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

# Enable Apache mod_rewrite
RUN a2enmod rewrite

EXPOSE 80