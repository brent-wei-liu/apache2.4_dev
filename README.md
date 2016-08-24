# apache2.4_dev

#config 
$ sudo vim /etc/apache2/apache2.conf
$ sudo apxs -i -a -c mod_myfilter.c &&  sudo apachectl restart

#install php5
$ sudo apt-get update
$ sudo apt-get install apache2
$ sudo apt-get install php5
$ sudo apt-get install libapache2-mod-php5
$ sudo apachectl restart

#Test PHP and get details about your PHP installation
The document root of the default web site is /var/www/html. We will now create a small PHP file (info.php) in that directory and call it in a browser. The file will display lots of useful details about our PHP installation, such as the installed PHP version.
nano /var/www/html/info.php

<?php
phpinfo();
?>
Then change the owner of the info.php file to the www-data user and group.
chown www-data:www-data /var/www/html/info.php

Now we call that file in a browser (e.g. http://192.168.1.100/info.php):
