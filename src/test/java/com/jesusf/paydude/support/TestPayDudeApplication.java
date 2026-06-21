package com.jesusf.paydude.support;

import com.jesusf.paydude.Application;
import org.springframework.boot.SpringApplication;

public class TestPayDudeApplication {

  public static void main(String[] args) {
    SpringApplication.from(Application::main).with(TestcontainersConfiguration.class).run(args);
  }

}