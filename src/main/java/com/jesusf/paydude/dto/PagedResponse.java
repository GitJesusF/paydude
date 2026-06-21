package com.jesusf.paydude.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import org.springframework.data.domain.Page;

import java.util.List;

/**
 * Framework-agnostic pagination wrapper for HTTP responses.
 *
 * <p>Spring Data's {@code Page<T>} (serialized as {@code PageImpl}) leaks internal framework
 * fields — {@code pageable}, {@code sort}, {@code unpaged}, {@code empty} — into the JSON
 * payload. Spring Boot 3.2+ explicitly warns against returning {@code PageImpl} directly because
 * its JSON structure is not part of any stable contract and may change across Spring Data
 * versions. This record is the stable HTTP contract: a minimal set of fields a paginated client
 * actually needs, owned by this codebase rather than by the framework.
 *
 * <p>Use {@link #from(Page)} at the controller boundary to convert the {@code Page<T>} returned
 * by the service layer into the wire shape. Services keep working with Spring Data abstractions
 * internally; only the boundary changes.
 *
 * @param content       the items of the current page
 * @param page          zero-based index of the current page
 * @param size          requested page size (may be larger than {@code content.size()} on the
 *                      last page)
 * @param totalElements total number of items across all pages
 * @param totalPages    total number of pages
 * @param hasNext       whether a subsequent page exists
 * @param <T>           element type of the page
 */
@Schema(description = "Stable pagination envelope wrapping a single page of results.")
public record PagedResponse<T>(

    @Schema(description = "The items on the current page.")
    List<T> content,

    @Schema(description = "Zero-based index of the current page.", example = "0",
        requiredMode = Schema.RequiredMode.REQUIRED)
    int page,

    @Schema(description = "Requested page size.", example = "20",
        requiredMode = Schema.RequiredMode.REQUIRED)
    int size,

    @Schema(description = "Total number of items across all pages.", example = "137",
        requiredMode = Schema.RequiredMode.REQUIRED)
    long totalElements,

    @Schema(description = "Total number of pages.", example = "7",
        requiredMode = Schema.RequiredMode.REQUIRED)
    int totalPages,

    @Schema(description = "Whether a subsequent page exists.", example = "true",
        requiredMode = Schema.RequiredMode.REQUIRED)
    boolean hasNext
) {

  /**
   * Converts a Spring Data {@link Page} into the stable wire envelope.
   *
   * @param page the page returned by the service layer
   * @param <T>  the element type
   * @return a {@code PagedResponse} carrying the same items and pagination metadata
   */
  public static <T> PagedResponse<T> from(Page<T> page) {
    return new PagedResponse<>(
        page.getContent(),
        page.getNumber(),
        page.getSize(),
        page.getTotalElements(),
        page.getTotalPages(),
        page.hasNext()
    );
  }
}
