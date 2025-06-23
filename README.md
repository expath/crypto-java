[![Build Status](https://github.com/expath/crypto-java/actions/workflows/ci.yml/badge.svg)](https://github.com/expath/crypto-java/actions/workflows/ci.yml)
[![Java 8+](https://img.shields.io/badge/java-8%2B-blue.svg)](https://adoptopenjdk.net/)
[![License](https://img.shields.io/badge/license-LGPL%202.1-blue.svg)](https://opensource.org/licenses/lgpl-2.1)
[![Maven Central](https://img.shields.io/maven-central/v/org.expath/crypto-java?logo=apachemaven&label=maven+central&color=green)](https://central.sonatype.com/search?namespace=org.expath)

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