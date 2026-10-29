//
// Created by adhokshajmishra on 9/10/20.
//

#ifndef FLEET_SSL_CERTIFICATE_H
#define FLEET_SSL_CERTIFICATE_H

#include <boost/asio/ssl/context.hpp>
#include <string>
#include <filesystem>
#include <iostream>

/*  Load a signed certificate into the ssl context, and configure
    the context for use with a server.

    For this to work with the browser or operating system, it is
    necessary to import the "Beast Test CA" certificate into
    the local certificate store, browser, or operating system
    depending on your environment Please see the documentation
    accompanying the Beast certificate for more details.
*/
inline
void
load_server_certificate(boost::asio::ssl::context& ctx, const std::string& ssl_certificate, const std::string& ssl_private_key,
                        const std::string& diffie_hellman_key, const std::string& private_key_password)
{
    try
    {
        if (!std::filesystem::exists(ssl_certificate))
        {
            std::cerr << "Error: SSL certificate file does not exist." << std::endl;
            return;
        }
        if (!std::filesystem::is_regular_file(ssl_certificate))
        {
            std::cerr << "Error: SSL certificate file is not a regular file." << std::endl;
            return;
        }
        if (std::filesystem::is_empty(ssl_certificate))
        {
            std::cerr << "Error: SSL certificate file is empty." << std::endl;
            return;
        }

        if (!std::filesystem::exists(ssl_private_key))
        {
            std::cerr << "Error: SSL private key does not exist." << std::endl;
            return;
        }
        if (!std::filesystem::is_regular_file(ssl_private_key))
        {
            std::cerr << "Error: SSL private key file is not a regular file." << std::endl;
            return;
        }
        if (std::filesystem::is_empty(ssl_private_key))
        {
            std::cerr << "Error: SSL private key file is empty." << std::endl;
            return;
        }

        if (!std::filesystem::exists(diffie_hellman_key))
        {
            std::cerr << "Error: Diffie-Hellman key file does not exist." << std::endl;
            return;
        }
        if (!std::filesystem::is_regular_file(diffie_hellman_key))
        {
            std::cerr << "Error: Diffie-Hellman key file is not a regular file." << std::endl;
            return;
        }
        if (std::filesystem::is_empty(diffie_hellman_key))
        {
            std::cerr << "Error: Diffie-Hellman key file is empty." << std::endl;
            return;
        }
    }
    catch (const std::filesystem::filesystem_error& error)
    {
        std::cerr << "Error (" << error.code() << ") while validating SSL file paths file path: " << error.what() << std::endl;
        return;
    }

    ctx.set_password_callback(
            [private_key_password](std::size_t,
               boost::asio::ssl::context_base::password_purpose)
            {
                return private_key_password;
            });

    ctx.set_options(
            boost::asio::ssl::context::default_workarounds |
            boost::asio::ssl::context::no_sslv2 |
            boost::asio::ssl::context::single_dh_use);

    // Set cipher suites compatible with osquery and modern TLS.
    // Every entry here uses (EC)DHE key exchange, i.e. forward secrecy —
    // deliberately excludes the plain-RSA-key-exchange ciphers
    // (AES256-GCM-SHA384 / AES128-GCM-SHA256 with no ECDHE/DHE prefix) that
    // were previously listed as a fallback: those don't provide forward
    // secrecy, so a compromise of the server's private key at any future
    // point would let past traffic captured under one of those ciphers be
    // decrypted retroactively. All clients that can do TLS 1.2 (osquery's
    // baseline) support at least one (EC)DHE suite, so this isn't a
    // compatibility trade-off.
    SSL_CTX_set_cipher_list(ctx.native_handle(),
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES256-SHA384:"
        "ECDHE-RSA-AES128-SHA256:"
        "DHE-RSA-AES256-GCM-SHA384:"
        "DHE-RSA-AES128-GCM-SHA256");

    // Use file-based loading — more robust across OpenSSL versions (handles PKCS#8, traditional PEM, etc.)
    ctx.use_certificate_chain_file(ssl_certificate);
    ctx.use_private_key_file(ssl_private_key, boost::asio::ssl::context::file_format::pem);
    ctx.use_tmp_dh_file(diffie_hellman_key);
}

#endif //FLEET_SSL_CERTIFICATE_H
