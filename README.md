[![CI](https://github.com/expath/crypto-java/workflows/CI/badge.svg)](https://github.com/expath/crypto-java/actions?query=workflow%3ACI)
[![Java 8+](https://img.shields.io/badge/java-8%2B-blue.svg)](https://adoptopenjdk.net/)
[![License](https://img.shields.io/badge/license-LGPL%202.1-blue.svg)](https://opensource.org/licenses/lgpl-2.1)
[![Maven Central](https://img.shields.io/maven-central/v/org.expath.crypto/crypto-java.svg?label=Maven%20Central)](https://search.maven.org/search?q=g:%22org.expath.crypto%22%20AND%20a:%22crypto-java%22)

# Java library for EXPath Crypto Module

This is a Java implementation of the [EXPath HTTP Crypto Module specification](http://expath.org/spec/crypto).

We provide a Java library that may be used as the basis for specific product implementations.

# Building from source
Requires:
* Java 1.8 or newer
* Maven 3.6 or newer

```bash
$ git clone https://github.com/expath/crypto-java.git
$ cd crypto-java
$ mvn clean package
```