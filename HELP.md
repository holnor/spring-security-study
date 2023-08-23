# Spring Security lépésről lépésre

Ennek a projektnek a keretén belül lépésről lépésre felépítünk egy Spring Security projektet.
A projekt egy banki alkalmazást fog szimulálni.
Az eredeti projekt, ami alapján haladni fogunk megtalálható
itt: https://www.udemy.com/course/spring-security-zero-to-master/
Az alkalmazásnak lesznek mindenki által elérhető részei (`/contact`, `/notices`), míg a többi végpontot levédjük

### -1.lépés - Spring Security működése

![img_1.png](img_1.png)

### 0. lépés - App security nélkül

1. indíts egy új Spring projectet
    - függőségek: spring boot web
   ```xml
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
   ```
2. Hozz létre egy kontrollert, aminek az egyik metódusa a `/welcome` végponton figyeli a get kéréseket, és egy Stringgel
   tér vissza.
3. Indítsd el a programot és nyisd meg a [localhost:8080/welcome]()  oldalt a böngésződben.
4. Láthatod, hogy a végpont tartalma jelenleg mindenki számára hozzáférhető.

### 1. lépés - Spring Security függőség hozzáadása

1. Add hozzá az alábbi függőséget:

```xml

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

2. Indítsd újra az alkalmazást, majd nézd meg a `/welcome` oldalt.
3. Láthatod, hogy `/login` oldalra jutottál, ahol be kell jelentkezned a folytatáshoz.
    - Akármennyi végpontod lenne, egyikhez se férsz hozzá, amíg be nem jelentkezel.
    - Az alkalmazás konolán megtalálod a generált jelszót a belépéshez.
    - A felhasználónév `user`
    - bejelntkezés után látható a kért végpont tartalma.
    - Újraindításnál új jelszó generálódik.
    - Minden látogatónak ugyanaz a jelszava és a felhasználóneve is.

4. Tedd statikussá a bejelntkezési adatokat az `application.properties`
   fájlban. (https://docs.spring.io/spring-boot/docs/current/reference/html/application-properties.html)

```properties
spring.security.user.name=username
spring.security.user.password=password
```

5. Nyisd meg a végpontot inkognitó módban (vagy töröld a sütik közül a `JSESSIONID`-t) és teszteld az újonnan beállított
   felhasználónevet és jelszót!
6. Készítsd el a az alábbi kontrollereket, és mindegyiknek legyen egy metódusa, ami egy Stringgel tér vissza és leírja,
   hogy épp hol vagyunk:
    - `AccountController`
      péda:
   ```java
   @GetMapping("/myAccount")
   public String getAccountDetail(){
   return "Here are the cards details from DB";
   }
   ```
    - `CardsController`
    - `LoanController`
    - `BalanceController`
    - `ContactController`
    - `NoticeController`

### 2. lépés - SecurityFilterChain beállítása

1. Alapértelmezetten minden végpont automatikusan zárva lesz, ezért explicit meg kell fogalmazni, ha valamely végponthoz
   nem szeretnénk bejelentkezéshez kötni az elérést
   ```java
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests.requestMatchers("/myAccount", "/myBalance", "/myLoans", "/myCards").authenticated()
                        .requestMatchers("/notices", "/contact").permitAll())
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }
   ```
    - A szűrőkről bővebben innen tájékozódj: https://docs.spring.io/spring-security/reference/servlet/architecture.html

### 3. lépés - Felhasználók definiálása és kezelése

Ahhoz, hogy megszüntethessük az `application.properties` fájlban rögzített belépési adatokat meg kell valósítanunk egy
másik bejelentkezési módot. Konkrétabban egy `UserDetailsManager` interfészt kell implementálni.

- Létezik egy `LdapUserDetailsManager` használata merülhet fel, de erre most nem térünk, mivel használata nem gyakori.
  - Az `InMemoryUserDetailsManager` alkalmazásával különböző felhasználókat álíthatunk be, különböző jogosultságokkal, de
    mindegyik paraméter beégetett, a belépési adatok kiolvashatók a kódból, stb ezért **ezt a módot ne használjuk** éles
    környezetben:

      ```java
         @Bean
    public InMemoryUserDetailsManager userDetailsService(){
            UserDetails admin=User.withDefaultPasswordEncoder()
            .username("admin")
            .password("12345")
            .authorities("admin")
            .build();
            UserDetails user=User.withDefaultPasswordEncoder()
            .username("user")
            .password("12345")
            .authorities("read")
            .build();
            return new InMemoryUserDetailsManager(admin,user);
            }
        ```
   
 - A `JdbcUserManager` már adatbázisból kezeli a felhasználókat, de mi tovább megyünk és JPA entitásokat hozunk létre a felhasználók kezelésére pedig egy saját `UserDetailsService` megvalósítást fogunk kidolgozni.(ha
  kipróbáltad az `InMemoryUserDetailsManager`-t, akkor azt most töröld!):

1. Csatlakoztass egy adatbázist a projekthez (Ennek lépéseire nem térek ki, a továbbiakban MySQL adatbázist használunk).

- **Ne felejtsd el megadni a szükséges beállításokat az `application.properties` fájlban!**

2. A `SecurityConfig` osztályon belül hozd létre azt a Beant, ami gondoskodni fog a jelszavak tárolásáról. Ez most egyelőre egy olyan megvalósítás lesz, ami sima szövegként tárolja majd a jelszavakat, de később ezt le fogjuk cserélni.
   
   ```java
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
      ```
   
3. Hozd létre a `Customer` entitást, legyen meg minden getter/setter:
   - id: Long
   - email: String
   - pwd: String
   - role: String

4. Hozd létre a `CustomerRepository` osztályt, ami a `JpaRepository` osztály megvalósítása.

5. Hozd létre a `BankUserDetails` osztályt (`@Service`), ami implementálja a `UserDetailsService` interfészt
   - Injektáld a `CustomerRepository`-t
   - A felülírandó metódus megvalósításában határozhatod meg, hogy mi alapján jöjjön létre egy új `User`.
   - Ez a `User` a Spring Security egyik osztálya, amit az autentikáció és az autorizáció során is használhatunk majd.
   ```java
       @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Customer customer = customerRepository.findByEmail(username).orElse(null);
        if (customer == null) {
            throw new UsernameNotFoundException("User details not found for the user : " + username);
        } else {
            String userName = customer.getEmail();
            String password = customer.getPwd();
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority(customer.getRole()));
            return new User(userName, password, authorities);
        }
    }
    ```
   
### 4. Jelszavak biztonságos tárolása
A jelszavakat nem tárolhatjuk egyszerű szövegként, helyette kódolt, titkosított, vagy hash-elt módon kell kezelni
- kódolt: könnyen visszafejthető
- titkosított: kulccsal fejthető csak vissza
- hashelt: A hashelő algoritmus birtokában összehasonlíthatunk két hash-elt jelszót, hogy egyezőek-e
Mi a hash-elt jelsókezelést választjuk, mert az így kezelt jelszó nem fejthető vissza

1. A `SecurityConfig` osztályban töröld a korábbi pw encodert és helyette készíts beant, ami egy `BCryptPasswordEncoder`-rel tér vissza:
    ```java
       @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

   ```
2. Add hozzá a szűrőkhöz a `/register` végpontot, hogy autentikáció nélkül is elérhető legyen és állítsd a csrf-t `disable()`-re
    - Ha ezekkel végeztlél, akkor a szűrő így néz ki:
    ```java
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.csrf((csrf) -> csrf.disable())
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/myAccount", "/myBalance", "/myLoans", "/myCards").authenticated()
                        .requestMatchers("/notices", "/contact", "/register").permitAll())
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

   ```
3. Hozd létre a `LoginController`-t
    - Injektáld a következőket: `CustomerRepository`, `PasswordEncoder`
    - Készíts egy metódust (`@PostMapping("/register")`) a regisztrációhoz:
    - Itt a lényeg, hogy a beérkező jelszót ne csak sima szövegként állítsuk be az entitáshoz, hanem az encoderen keresztül hash-elve: `passwordEncoder.encode(customer.getPwd()`
    - A metódusunk valahogy így fog kinézni:
   ```java
    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody Customer customer) {
        Customer savedCustomer = null;
        ResponseEntity response = null;
        try {
            String hashPwd = passwordEncoder.encode(customer.getPwd());
            customer.setPwd(hashPwd);
            savedCustomer = customerRepository.save(customer);
            if (savedCustomer.getId() > 0) {
                response = ResponseEntity
                        .status(HttpStatus.CREATED)
                        .body("Given user details are successfully registered");
            }
        } catch (Exception ex) {
            response = ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An exception occured due to " + ex.getMessage());
        }
        return response;
    }
    ```
4. Regisztrálj egy felhasználót Postman-en keresztül.
5. Ha mindent jól csináltunk, akkor az adatbázisban a jelszó oszlopában a hash-elt jelszót látod már.
    - Bejelentkezéskor a `BankUserDetails` gondoskodik a jelszavak összehasonlításáról
      - Mivel implementálja a `UserDetailsService` osztályt, ezért hozzáférése lesz a Spring alapértelmezett autentikációt biztosító osztályához, a `DaoAuthenticationProvider`-hez
      - A providernek van egy metódusa, ami a bean-né tett encoder alapján össze tudja hasonlítani a jelszavakat.

### 5. lépés - Egyedi AuthenticationProvider implementáció
Azért lehet szükséges az egyéni implementáció, mert előfordulhat olyan helyzet, hogy a belépést egyéni logikához szeretnénk kötni, pl.:
    - Többféle bejelentkezési módot is meg szeretnénk valósítani (pl. oauth2)
    - Nem engedélyezett a belépés, csak bizonyos országokból.

Az egyedi megvalósításhoz az alábbiakat kell tenni:

1.  Hozz létre egy új osztályt, ami implementálja az `AuthenticationProvider` interfészt
   - annotáld komponensként (`@Component`)
   - Injektáld a `CustomerRepository`-t és a `PasswordEncoder`-t
2. Valósítsd meg mindkét szükséges metódust:
   - A `supports(Class<?> authentication)` metódust megkeresheted a `DaoAuthenticationProvider` osztályban, és egy az egye idemásolhatod.

   ```java
   @Override
   public boolean supports(Class<?> authentication) {
   return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
   }
      ```
   - Az `authenticate(Authentication authentication)` metóduson belül tudod megírni a bejelentkeztetési logikát. Mi most az egyszerűség kedvéért nem kötünk ki további feltételeket, de figyeld meg, hogy a jelszavak összehasonlítását is explicit módon ki kell dolgozni!

   ```java
   @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String pwd = authentication.getCredentials().toString();
        Customer customer = customerRepository.findByEmail(username).orElse(null);
        if (customer != null) {
            if (passwordEncoder.matches(pwd, customer.getPwd())) {
                List<GrantedAuthority> authorities = new ArrayList<>();
                authorities.add(new SimpleGrantedAuthority(customer.getRole()));
                return new UsernamePasswordAuthenticationToken(username, pwd, authorities);
            } else {
                throw new BadCredentialsException("Invalid password!");
            }
        }else {
            throw new BadCredentialsException("No user registered with this details!");
        }
    }
      ```
   - További különbség, hogy Itt már nem egy `User`-rel, hanem egy `UsernamePasswordAuthenticationToken`-nel térünk vissza sikeres autentikáció esetén.
     - a `UsernamePasswordAuthenticationToken` lehetőséget biztosít arra, hogy a hitelesítési adatokat átadják az autentikációs folyamathoz, míg a `User` osztály teljes felhasználói adatokat reprezentál, és általában az alkalmazás belső részéhez kapcsolódik.  
3. Jelenleg két osztályunk gondoskodik a bejelentkeztetésről és a Spring dönt, hogy melyik lép érvénybe. Mi az egyéni megvalósításunkkal fogunk továbbhaladni, így a beépített megoldásra nincs szükségünk: töröld azt az osztályt! 

### 6. lépés - CORS és CRSF
