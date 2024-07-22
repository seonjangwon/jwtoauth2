package com.security.jwtoauth2.repository;

import com.security.jwtoauth2.entity.RefreshEntity;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshRepository extends JpaRepository<RefreshEntity,Long> {

    Boolean existsByRefresh(String refresh);

    @Transactional
    void deleteByRefresh(String refresh); // 이거도 실 프로젝트에서는 다르게 사용하던지
}
