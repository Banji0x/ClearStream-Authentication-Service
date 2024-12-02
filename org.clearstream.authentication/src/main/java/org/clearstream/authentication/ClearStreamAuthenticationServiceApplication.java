package org.clearstream.authentication;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class ClearStreamAuthenticationServiceApplication {

  public static void main(String[] args) {
    SpringApplication.run(ClearStreamAuthenticationServiceApplication.class, args);
  }

}
