package com.auth_system.authentication.system.auth.domain;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;


@Repository
interface UserRepository extends JpaRepository<UserAuth,Integer> {
    UserAuth findByUsername(String username);
    @Query("Select u From UserAuth u where u.username = ?1 or u.email = ?2")
    UserAuth findByUsernameOrEmail(String username, String email);
}
