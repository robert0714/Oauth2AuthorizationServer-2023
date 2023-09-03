package com.demo.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.demo.auth.entity.Client;

public interface ClientRepository extends JpaRepository<Client, String> {

	Optional<Client> findByClientId(String clientId);
}