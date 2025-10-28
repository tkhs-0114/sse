package oit.is.z4272z2911.sse.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class Sample3AuthConfiguration {
  /**
   * 認可処理に関する設定（認証されたユーザがどこにアクセスできるか）
   *
   * @param http
   * @return
   * @throws Exception
   */
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.formLogin(login -> login
        .permitAll())
        .logout(logout -> logout
            .logoutUrl("/logout")
            .logoutSuccessUrl("/")) // ログアウト後に / にリダイレクト
        .authorizeHttpRequests(authz -> authz
            .requestMatchers("/sample5/**").authenticated() // /sample3/以下は認証済みであること
            .anyRequest().permitAll()) // 上記以外は全員アクセス可能
        .csrf(csrf -> csrf
            .ignoringRequestMatchers("/h2-console/*", "/sample2*/**")) // sample2用にCSRF対策を無効化
        .headers(headers -> headers
            .frameOptions(frameOptions -> frameOptions
                .sameOrigin()));
    return http.build();
  }

  /**
   * 認証処理に関する設定（誰がどのようなロールでログインできるか）
   *
   * @return
   */
  @Bean
  public InMemoryUserDetailsManager userDetailsService() {

    // ユーザ名，パスワード，ロールを指定してbuildする
    // このときパスワードはBCryptでハッシュ化されているため，{bcrypt}とつける
    // ハッシュ化せずに平文でパスワードを指定する場合は{noop}をつける
    // */p@ss

    UserDetails customer1 = User.withUsername("CUSTOMER1")
        .password("{bcrypt}$2y$05$mHmxp39k8KT9qQPoD6KSq.kEtntbCuradiTGOW.UeAnyjmUamI1U.").roles("CUSTOMER").build();
    UserDetails customer2 = User.withUsername("CUSTOMER2")
        .password("{bcrypt}$2y$05$nlVcI5AbV1pZqvbMf8..I.elnQ.MPnz3CYsWZ06nzVV0v6eta5pHq").roles("CUSTOMER").build();
    UserDetails seller = User.withUsername("SELLER")
        .password("{bcrypt}$2y$05$vcS33XL.bRyq1YERHM0Qf.iqEvcgwXYfwZsLEWbmPJYrzW2KZkIXm").roles("SELLER").build();

    // 生成したユーザをImMemoryUserDetailsManagerに渡す（いくつでも良い）
    return new InMemoryUserDetailsManager(customer1, customer2, seller);
  }

}
