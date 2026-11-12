<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.algologguard</groupId>
    <artifactId>decentralized-security-log-integrity</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>

    <name>Decentralized Security Log Integrity System Using Algorand</name>
    <description>Tamper-evident security log audit platform backed by Java 17, MySQL/SQLite JDBC, SHA-256, and the Algorand Blockchain.</description>

    <properties>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <dependencies>
        <!-- Official Algorand Java SDK -->
        <dependency>
            <groupId>com.algorand</groupId>
            <artifactId>algosdk</artifactId>
            <version>2.4.0</version>
        </dependency>

        <!-- MySQL JDBC Driver -->
        <dependency>
            <groupId>com.mysql</groupId>
            <artifactId>mysql-connector-j</artifactId>
            <version>8.3.0</version>
        </dependency>

        <!-- SQLite JDBC Driver (Optional Zero-Config Local DB) -->
        <dependency>
            <groupId>org.xerial</groupId>
            <artifactId>sqlite-jdbc</artifactId>
            <version>3.45.1.0</version>
        </dependency>
    </dependencies>

    <build>
        <sourceDirectory>.</sourceDirectory>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.11.0</version>
                <configuration>
                    <includes>
                        <include>AlgorandLogIntegritySystem.java</include>
                    </includes>
                </configuration>
            </plugin>
            <plugin>
                <groupId>org.codehaus.mojo</groupId>
                <artifactId>exec-maven-plugin</artifactId>
                <version>3.1.0</version>
                <configuration>
                    <mainClass>AlgorandLogIntegritySystem</mainClass>
                </configuration>
            </plugin>
        </plugins>
    </build>
</project>