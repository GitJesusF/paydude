package com.jesusf.paydude.config.web;

import com.jesusf.paydude.config.WebConfig;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Marker that prefixes every annotated controller with {@code /v1} (see {@link WebConfig}). */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface ApiV1 {
}