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
    - Az `InMemoryUserDetailsManager` alkalmazásával különböző felhasználókat álíthatunk be, különböző jogosultságokkal,
      de
      mindegyik paraméter beégetett, a belépési adatok kiolvashatók a kódból, stb ezért **ezt a módot ne használjuk**
      éles
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

- A `JdbcUserManager` már adatbázisból kezeli a felhasználókat, de mi tovább megyünk és JPA entitásokat hozunk létre a
  felhasználók kezelésére pedig egy saját `UserDetailsService` megvalósítást fogunk kidolgozni.(ha
  kipróbáltad az `InMemoryUserDetailsManager`-t, akkor azt most töröld!):

1. Csatlakoztass egy adatbázist a projekthez (Ennek lépéseire nem térek ki, a továbbiakban MySQL adatbázist használunk).

- **Ne felejtsd el megadni a szükséges beállításokat az `application.properties` fájlban!**

2. A `SecurityConfig` osztályon belül hozd létre azt a Beant, ami gondoskodni fog a jelszavak tárolásáról. Ez most
   egyelőre egy olyan megvalósítás lesz, ami sima szövegként tárolja majd a jelszavakat, de később ezt le fogjuk
   cserélni.

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

1. A `SecurityConfig` osztályban töröld a korábbi pw encodert és helyette készíts beant, ami egy `BCryptPasswordEncoder`
   -rel tér vissza:
    ```java
       @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

   ```
2. Add hozzá a szűrőkhöz a `/register` végpontot, hogy autentikáció nélkül is elérhető legyen és állítsd a
   csrf-t `disable()`-re
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
    - Itt a lényeg, hogy a beérkező jelszót ne csak sima szövegként állítsuk be az entitáshoz, hanem az encoderen
      keresztül hash-elve: `passwordEncoder.encode(customer.getPwd()`
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
        - Mivel implementálja a `UserDetailsService` osztályt, ezért hozzáférése lesz a Spring alapértelmezett
          autentikációt biztosító osztályához, a `DaoAuthenticationProvider`-hez
        - A providernek van egy metódusa, ami a bean-né tett encoder alapján össze tudja hasonlítani a jelszavakat.

### 5. lépés - Egyedi AuthenticationProvider implementáció

Azért lehet szükséges az egyéni implementáció, mert előfordulhat olyan helyzet, hogy a belépést egyéni logikához
szeretnénk kötni, pl.:

- Többféle bejelentkezési módot is meg szeretnénk valósítani (pl. oauth2)
- Nem engedélyezett a belépés, csak bizonyos országokból.

Az egyedi megvalósításhoz az alábbiakat kell tenni:

1. Hozz létre egy új osztályt, ami implementálja az `AuthenticationProvider` interfészt

- annotáld komponensként (`@Component`)
- Injektáld a `CustomerRepository`-t és a `PasswordEncoder`-t

2. Valósítsd meg mindkét szükséges metódust:
    - A `supports(Class<?> authentication)` metódust megkeresheted a `DaoAuthenticationProvider` osztályban, és egy az
      egye idemásolhatod.

   ```java
   @Override
   public boolean supports(Class<?> authentication) {
   return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
   }
      ```
    - Az `authenticate(Authentication authentication)` metóduson belül tudod megírni a bejelentkeztetési logikát. Mi
      most az egyszerűség kedvéért nem kötünk ki további feltételeket, de figyeld meg, hogy a jelszavak
      összehasonlítását is explicit módon ki kell dolgozni!

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
    - További különbség, hogy Itt már nem egy `User`-rel, hanem egy `UsernamePasswordAuthenticationToken`-nel térünk
      vissza sikeres autentikáció esetén.
        - a `UsernamePasswordAuthenticationToken` lehetőséget biztosít arra, hogy a hitelesítési adatokat átadják az
          autentikációs folyamathoz, míg a `User` osztály teljes felhasználói adatokat reprezentál, és általában az
          alkalmazás belső részéhez kapcsolódik.
3. Jelenleg két osztályunk gondoskodik a bejelentkeztetésről és a Spring dönt, hogy melyik lép érvénybe. Mi az egyéni
   megvalósításunkkal fogunk továbbhaladni, így a beépített megoldásra nincs szükségünk: töröld azt az osztályt!

### 6. lépés - CORS és CRSF

Ahhoz hogy tovább tudjunk lépni, fel kell építeni az alaklmazás frontend részét. Ennek menetére nem térünk ki
részletesen.

- **Az új kódokat a "create new codebase for step#6" commit tartalmazza**
- Mivel ez nem egy MVC vagy Angular bemutató, ezért az ezekkel kapcsolatos lépésekre nem térünk ki.

0. Dobd el az eddigi táblákat, futtasd a projektet, majd a project `resources` mappájában található `script.sql`
   futtatásával töltsd fel az adatbázist néhány adattal. Szánj rá kb fél órát, hogy megismerd az újonnan létrehozott
   osztályokat és az Angular projectet!
1. Hozz létre Postman-nel egy új felhasználót!
2. Indítsd el a frontendet (előtte `npm i`, ha még nem tetted!) és próbálj bejelntkezni a `localhost:4200/login`
   oldalon.
    - Nyisd meg a böngészőben a konzolt és nézd meg milyen hibát kaptál.
    - A böngésző alapbeállítása, hogy megvédje az adatot/kommunikációt és ne engedje annak megosztását két különböző
      domain között. (CORS)
    - Figyelembe vett különbségek:
        - különböző séma: HTTP vagy HTTPS
        - különböző port: localhost:8080 vagy localhost:4200
        - különböző domain: https://domain1.com vagy https://domain2.com
        - A beállítás elvégezhető annotáció használatával is `@CrossOrigin(origins = "http://localhost:4200")`, de sok
          ismétlődést, és nehezen kezelhetőséget eredményezne, ezért mi nem így fogjuk elvégezni a beállítást
3. A CORS globális beállításához nyisd meg a `SecurityConfig` osztályt, és módosítsd a szűrőláncot erre:
   ```java

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration config = new CorsConfiguration();
                        config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                        config.setAllowedMethods(Collections.singletonList("*"));
                        config.setAllowCredentials(true);
                        config.setAllowedHeaders(Collections.singletonList("*"));
                        config.setMaxAge(3600L);
                        return config;
                    }
                })).csrf((csrf) -> csrf.disable())
                .authorizeHttpRequests((requests)->requests
                        .requestMatchers("/myAccount", "/myBalance", "/myLoans", "/myCards", "/user").authenticated()
                        .requestMatchers("/notices", "/contact", "/register").permitAll())
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }
   ```

   Látható, hogy a korábbi metódust a cors beállításokkal bővítettük:
    - `setAllowedOrigins`: itt határozhatod meg, hogy mik azok az eredetitől eltérő címek, amik engedélyezettek
    - `setAllowedMethods`: engedélyezett metódusok "*" = minden
    - `setAllowCredentials`: Ha true, akkor a böngésző engedélyezi a JavaScriptnek, hogy hozzáférjen a kéréshez küldött
      adatokhoz, például sütikhez vagy HTTP hitelesítési információkhoz, amikor azokat egy másik eredeti (domain) címről
      történő kéréstől kapja.
    - `setAllowedHeaders`: Beállíthtó hogy a JS milyen HTTP fejlécet küldhet. Egyelőre mindent engedélyezünk
    - `config.setMaxAge`: A böngésző érzékeli, hogy másik eredetiről érkezik kérés, de alapértelmezetten minden
      alkalommal elküld egy preflight kérést, viszont ha beállítunk egy mp alapú időkeretet, akkor a megadott időn belül
      biztosított a hozzáférés kérelem nélkül is az azonos erőforrások esetén

Korábban megfigyelhetted, hogy a csrf ki van kapcsolva. Erre azért volt szükség, mert a Spring Security
alapértelmezetten neme engedélyezi a POST/PUT/DELETE/PATCH műveleteket, így nem tudtunk volna pl. új felhasználót
létrehozni.
A csrf támadás során a hacker megpróbál rávenni, hogy kattints egy linkre, ami a háttérben pl. egy post kérést indít pl.
a facebook felé, hogy megváltoztassa a felhasználó email címét.
Ha a facebook nem védekezik a csrf támadás ellen, és ha ez a kérés ugyanabból a böngészőből indul, és a felhasználó be
van jelentkezve, akkor a hacker ki tudja cserélni az email címet.
Éppen ezért:

**Éles környezetben soha ne kapcsold ki a csrf védelmet!**

4. Hozz létre egy osztályt, ami a `OncePerRequestFilter' absztrakt osztály leszármazottja.
    - írd fölül a `doFilterInternal` metódust
        - hozz létre egy új `CsrfToken`-t a requestből kinyerhető csrf token alapján
        - ha a token header neve nem null, akkor állítsd be a válasz headert a token alapján

   ```java
   public class CsrfCookieFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if(null != csrfToken.getHeaderName()){
            response.setHeader(csrfToken.getHeaderName(), csrfToken.getToken());
        }
        filterChain.doFilter(request, response);
       }
   }
   ```   
   Ezt az osztályt be fogjuk kötni a szűrőbe, hogy az alaklmazás képes legyen minden kéréshez tokent küldeni

5. A CSRF beállításhoz módosítsd a szűrőt az alábbi szerint:

   ```java
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        requestHandler.setCsrfRequestAttributeName("_csrf");

        http.securityContext((context) -> context
                        .requireExplicitSave(false))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
                .cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration config = new CorsConfiguration();
                        config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                        config.setAllowedMethods(Collections.singletonList("*"));
                        config.setAllowCredentials(true);
                        config.setAllowedHeaders(Collections.singletonList("*"));
                        config.setMaxAge(3600L);
                        return config;
                    }
                })).csrf((csrf) -> csrf.csrfTokenRequestHandler(requestHandler).ignoringRequestMatchers("/contact", "/register")
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
                .authorizeHttpRequests((requests)->requests
                        .requestMatchers("/myAccount", "/myBalance", "/myLoans", "/myCards", "/user").authenticated()
                        .requestMatchers("/notices", "/contact", "/register").permitAll())
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }
   ```

Ha helyesen konfiguráltuk a csrf beállításokat, akkor az oldalunk egy random módon generált CSRF Tokent ad hozzá rejtett
paraméterként a felhasználó session-jéhez.
Ha a felhasználó rákattint a támadó linkjére, akkor a kérést a szerverünk 403-as hibakóddal el fogja utasítani, mivel a
kérés nem rendelkeznek a megfelelő CSRF tokennel.

Nézzük meg mi is történt a fenti kódban:

- `CsrfTokenRequestAttributeHandler` : A CsrfTokenRequestHandler interfész implemetációja, amely képes a CsrfTokent
  kérés attribútumként elérhetővé tenni, és a token értékét a kérés fejléceként vagy paraméterértékeként feloldani.
- A metódusláncon belül:
    - `securityContext`: ez a konfiguráció azt mondja meg a Spring Security-nek, hogy az azonosításokat automatikusan
      mentse és mindig hozzon létre munkameneteket a felhasználók számára, amikor szükség van rájuk. Ennek a két sornak
      köszönhetően nem kell minden alkalommal megosztani a credentials-t az Angular alkalmazással
    - meghatározzuk a tokenkezelő objektumot
    - beállítjuk, hogy mely végpontokat hagyja figyelmen kívül
    - `.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())`: a csrf tokent a böngésző küldi a szervernek
      minden kérés mellé, de alapértelmezetten a JS ezt nem teheti meg, ezért explicit módon fel kell oldani az erre
      vonatkozó szabályt
    - `addFilterAfter`: közbeiktatja az egyedi szűrőnket, miután a basic autentikáció megtörtént.

6. Frontenden is gondoskodni kell a csrf token kezeléséről:
    - A `login.component.ts` fájlon belül egészítsd ki két sorral a `validateUser` funkciót, és importáld a szükséges
      függőséget:

   ```typescript
        let xsrf = getCookie('XSRF-TOKEN')!;
        window.sessionStorage.setItem("XSRF-TOKEN", xsrf);
   ```
    - Spring Security "XSRF-TOKEN" névvel fogja küldeni a sütit, míg a böngészőtől "X-XSRF-TOKEN" néven várja. Következő
      lépésként ezért az interceptorban be kell állítani a headert ennek megfelelően. Ehhez egészítsd ki
      az `app.request.interceptor.ts` fájlt:
   ```typescript
        let xsrf = sessionStorage.getItem('XSRF-TOKEN');
    if (xsrf){
      httpHeaders = httpHeaders.append('X-XSRF-TOKEN', xsrf);
    }
   ```
    - Eztkövetően már minden egyes kérésnél visszaküldi a tokent a böngésző (kivéve: nem bejelntkezett felhasználó és le
      nem védett végpontok esetén)
    - Ellenőrizd a sütiket a böngésző konzolán! Bejelntkezés után már nem csak a JSESSIONID, de az XSRF-TOKEN is ott
      kell legyen

### 7. lépés - Autorizáció

A sikeres autentikációt az autorizáció követi: Miután azonosítottuk magunkat, igazolnunk kell, hogy meg van a szükséges
felhatalmazásunk az oldal használni kívánt funkciójához
A projekt jelenlegi állapotában regisztráció során minden felhasználónak beállítjuk a `role` fieldjét
automatikusan `"user"`-re, de fejlesztéseink révén szeretnénk majd elérni, hogy több szerepkört is ki lehessen osztani.

1. Hozz létre egy új entitást: Authority
    - id: Long
    - name: String
    - customer: Customer (@ManyToOne @JoinColumn(name="customer_id"))

2. Add hozzá a Customer fieldjeihez az alábbit és készíts hozzá gettert/settert
   ```java
    @JsonIgnore
    @OneToMany(mappedBy = "customer", fetch = FetchType.EAGER)
    private Set<Authority> authorities;
   ```
3. Hozz létre egy segédmetódust a `BankUsernamePasswordProvider` osztályban! Ez a metódus létrehoz
   egy `GrantedAuthorities` listát a bemeneti string lista alapján. Ez a metódus tulajdonképpen a 38-39.sor
   kiszervezése:
   ```java
    private List<GrantedAuthority> getGrantedAuthorities(Set<Authority> authorities) {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        for (Authority authority : authorities) {
            grantedAuthorities.add(new SimpleGrantedAuthority(authority.getName()));
        }
        return grantedAuthorities;
    }
   ```
4. Az `authenticate` metódusban a visszatérési érték `authorities` paraméterét cseréld ki a metódussal, majd töröld ki a
   sorokat, amiket kivált.

   ```java
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String pwd = authentication.getCredentials().toString();
        Customer customer = customerRepository.findByEmail(username).orElse(null);
        if (customer != null) {
            if (passwordEncoder.matches(pwd, customer.getPwd())) {
                return new UsernamePasswordAuthenticationToken(username, pwd, getGrantedAuthorities(customer.getAuthorities()));
            } else {
                throw new BadCredentialsException("Invalid password!");
            }
        }else {
            throw new BadCredentialsException("No user registered with this details!");
        }
    }
   ```
5. Töltsd fel adattal az autorities táblát
   ```sql
   INSERT INTO `authorities` (`customer_id`, `name`)
   VALUES (1, 'VIEWACCOUNT');
   
   INSERT INTO `authorities` (`customer_id`, `name`)
   VALUES (1, 'VIEWCARDS');
   
   INSERT INTO `authorities` (`customer_id`, `name`)
   VALUES (1, 'VIEWLOANS');
   
   INSERT INTO `authorities` (`customer_id`, `name`)
   VALUES (1, 'VIEWBALANCE');
   ```

6. Tegyél egy breakpointot az `authenticate` metódus második sorára, majd futtasd a programut debug módban és jelentkezz
   be! A customer fieldjei között meg kell jelenjen az authorities lista
   ![img.png](img.png)

7. Ezt követően átállíthatjuk a szűrőnket, hogy bizonyos végpontok csak akkor legyenek hozzáférhetők, ha a felhasználó
   rendelkezik bizonyos jogosultságokkal.
   Ha szeretnéd tesztelni, akkor megteheted, hogy kitörölsz egy jogosultságot az adatbázisból, és felkeresed az ahhoz
   tartozó végpontot. Az eredmény 403-as hbakód lesz
   ```java
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
                        .requestMatchers("/myBalance").hasAnyAuthority("VIEWACCOUNT", "VIEWBALANCE")
                        .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
                        .requestMatchers("/myCards").hasAuthority("VIEWCARDS")
                        .requestMatchers("/user").authenticated()
                        .requestMatchers("/notices", "/contact", "/register").permitAll())
   ```

Már egy közepes méretű alkalmazásnál is átláthatatlanná válhat a fenti megközelítés. Ennek áthidalása végett
használhatsz a jogosultságok helyett szerepköröket (authority vs. role)
A role-okkal csoportosíthatod a jogosultságokat. Alakítsuk át a jelenlegi autorizációt és használjunk helyette
szerepköröket! Ezt gyorsan meg tudjuk valósítani, mivel ugyanazt az interfészt kell implementálni. Egy dologra kell
fokozottan odafigyelni, hogy a Spring Security számára jelezni kell a különbséget role és autorizáció között.
Ha valamit role-ként definiálsz, akkor azt minden esetben **"ROLE_"** előtaggal kell ellátnod. Pl.: `ROLE_USER`

1. Töröld ki a jelenlegi jogosultságokat az `authorities` táblából, és helyettük vegyél fel role-okat
   ```sql
   DELETE FROM `authorities`;
   
   INSERT INTO `authorities` (`customer_id`, `name`)
   VALUES (1, 'ROLE_USER');
   
   INSERT INTO `authorities` (`customer_id`, `name`)
   VALUES (1, 'ROLE_ADMIN');
   ```

2. A szűrőben cseréld ki a `hasAuthority`, `hasAnyAuthority` metódusokat `hasRole` és `hasAnyRole` metódusokra, és
   paraméterként használd a szerepköröket. Figyelj rá, hogy a metódus string formában kéri a paramétert, és "ROLE_"
   előtagot nem kell megadnod!

   ```java
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/myAccount").hasRole("USER")
                        .requestMatchers("/myBalance").hasAnyRole("USER","ADMIN")
                        .requestMatchers("/myLoans").hasRole("USER")
                        .requestMatchers("/myCards").hasRole("USER")
                        .requestMatchers("/user").authenticated()
                        .requestMatchers("/notices","/contact","/register").permitAll())

   ```

### 8. lépés - Saját szűrő használata

A korábbi lépések során már létrehoztunk egy egyéni szűrőt, hogy képesek legyünk csrf tokenek átadásra/fogadására. Ebben
a lépésben kicsit részletesebben is bemutatjuk a kapcsolódó tudnivalókat.
A filter tulajdonképpen az első réteg, amivel szembetalálkozik egy beérkező kérés. Habár ismerünk már néhány beépített
szűrőt (pl.: BasicAuthenticationFilter),
nem árt tudni, hogy a szűrők láncolatához saját szűrőt is hozzáadhatunk. Néhány példa, hogy miért lehet szükség erre:

- Ip címek loggolása
- adatok kódolás bejelentkezés előtt
- többlépcsős azonosítás (OTP... nem a bank: One-Time Password)

És még sorolhatnánk. Minden ezekhez hasonló esetben módosítani kell a szűrőláncot, és gyakran saját szűrőt kell
közbeiktatni.
Javaslom, hogy keresd meg a `FilterChainProxy` osztályt, és tanulmányozd a benne megírt metódusokat!
Mélyrehatóan tudod tanulmányozni a működésüket, ha elvégzed az alábbi beállításokat, majd debugger módban indítod el az
aplikációt:

- az appot annotálod a következővel: `@EnableWebSecurity(debug=true)`
- application.properties-ben: `logging.level.org.springframework.security.web.FilterChainProxy=DEBUG`

**!!! Ezt a beállítást kizárólag fejlesztés közben használd! Éles környezetben ezekkel a beálításokkal érzékeny adatok
kerülhetnek nyivánosságra.**
És a továbbhaladáshoz sincs szükség rá, úgyhogy töröld a fenti beállításokat, ha már végeztél a tanulmányozással!

1. Implementálnunk kell a `Filter` interfészt (jakarta.servlet).
   A létrehozott osztályunkban így meg kell valósítani a `doFilter` metódust, ami három paramétert fogad:
    - HttpServletRequest: kérés kezelésére
    - HttpServletResponse: válasz kezelésére
    - FilterChain: szűrőláncba építéshez

2. Miután megírtuk a szűrő logikáját, beilleszthetjük a szűrőláncba. Ezt három lehetőség közül válasthatjuk meg hogyan
   kivitelezzük:
    - .addfilterBefore(new EgyéniSzűrőOsztályNeve(), SzűrőOsztályAmiElőttHasználjuk) - pl validálás
    - .addfilterAfter(new EgyéniSzűrőOsztályNeve(), SzűrőOsztályAmiutánHasználjuk) - pl loggolás
    - .addfilterAt(new EgyéniSzűrőOsztályNeve(), SzűrőOsztályAmivelEgyüttHasználjuk) - sorrend nem befolyásolható!

Próbáljunk ki egyet a gyakorlatban!

```java
   import jakarta.servlet.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.logging.Logger;

public class AuthoritiesLoggingAfterFilter implements Filter {

    private final Logger LOG =
            Logger.getLogger(AuthoritiesLoggingAfterFilter.class.getName());

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (null != authentication) {
            LOG.info("User " + authentication.getName() + " is successfully authenticated and "
                    + "has the authorities " + authentication.getAuthorities().toString());
        }
        chain.doFilter(request, response);
    }

}
   ```

Miután ezt létrehoztad, illeszd be a szűrőláncba azáltal, hogy hozzáadod ezt a sort az `.authorizeHttpRequests` elé:

   ```java
       .addFilterAfter(new AuthoritiesLoggingAfterFilter(),BasicAuthenticationFilter.class)

```

Indítsd újra a programot, és jelentkezz be az oldalon, majd figyeld meg, hogy a kódszerkesztő konzolán megjelent a
kívánt log.

##### GenericFilterBean és OncePerRequestFilter

Úgy is megoldható az egyéni szűrő létrehozása, ha a fenti két interfész valamelyikét implementáljuk

##### GenericFilterBean:

- Az AbstractAuthenticationProcessingFilter ősosztálya.
- Általános célú szűrőként használható, amelyek nem feltétlenül kapcsolódnak az azonosítás és az engedélyezés
  folyamatához.
- Nem biztosítja az automatikus egyszerre futás ellenőrzést, tehát nem garantálja, hogy a szűrő csak egyszer fut le
  minden kérés esetén.
  -Használatra példa: ha egy általános célú szűrőt kívánsz létrehozni, amely nem szorosan kapcsolódik az
  azonosításhoz vagy engedélyezéshez, és nincs szükség rá, hogy minden kérés esetén csak egyszer fusson le.

##### OncePerRequestFilter:

- Garantálja, hogy a szűrőt minden HTTP kérés esetén csak egyszer hajtja végre, és nem ismétli meg a feldolgozást, ha a
  kérés további szűrőket vagy kezelőkét érint.
- Gyakran használják olyan szűrőknél, amelyek közvetlenül kapcsolódnak az azonosítás és az engedélyezés folyamatához,
  például az autentikációs vagy jogosultság-ellenőrző szűrőknél.
- Használatra példa: Ha egy szűrőt kívánsz készíteni, amely közvetlenül kapcsolódik az azonosításhoz vagy
  engedélyezéshez, és biztosítani akarod, hogy a szűrőd csak egyszer fusson le minden kérés esetén, még akkor is, ha
  több
  további szűrőt vagy kezelőt alkalmaznak a kérés során.

### 9. lépés - Token alapú autentikáció (JWT)

Az előző lépés végére felépítettünk egy olyan biztonsági rendszert, mely alkalamas lehet egy kisebb projekt, vagy egy
csupán tűzfalon belül működő alkalmazás levédésére.
Viszont ha enterprise méretű, vagy a teljes interneten hozzáférhető alkalmazásunk van, akkor nem lesz elegendő számunkra
a JSESSIONID.
Egy olyan tokent kell legyártanunk, amely képes több információt is tárolni a felhasználóról, és amit titkosítással
tudunk védeni.
Erre szolgál megoldásként a JWT alapú bejelentkeztetés. Leginkább ahhoz hasonlítható a módszer, mint amikor vendégként
első alkalommal megjelensz
egy szálloda recepciójánál. Bemutatod a személyidet, a foglalási azonosítódat, stb. majd kapsz a recepcióstól egy
kulcskártyát, amivel eztán az egész hotel területén mozoghatsz.
Bejuthatsz az étterembe, a bárba, vagy ha a csomagod tartalmazza, akkor a wellness részlegre és az edzőtermekhez. Ha
elvesztenéd a kulcsot, akkor odasétálsz a recepcióshoz, újra azonosítod magad, a recepciós pedig érvényteleníti az
elveszett kártyát, ami helyett kiállít egy másikat.
A mostani lépésben ezt fogjuk megvalósíteni.

A JWT token három részből áll, amiből a harmadik opcionális:

- header: metaadatok
- playload: felhasználóról információ
- aláírás: hitelesítésben játszik szerepet

A token első két tagja csupán Base64 alapú kódolással védett, ám ez könnyedén visszafejthető és így a tartalom
szerkeszthető.
Éppen ezért mi felhasználjuk az aláírás adta lehetőséget a még biztonságosabb bejelentkeztetéshez. Az aláírás ugyanis
nem kódolt, hanem titkosított.
Mi egy hash-elési technikával fogjuk ezt elérni, azaz nem lesz mód az aláírás visszafejtésére, ám a backendünk tudni
fogja, hogy hiteles-e az aláírás.
Az aláírás alapja a header és a playload, ami ha illetéktelen kezébe kerülne, aki módosítani akarja a tartalmát, azt
ugyan megteheti, ám az aláírás miatt
nem fog átjutni a bejelentkezésen, mivel a módosított tartalom miatt a hash nem fog egyezni.

1. Függőségek importálása:
   ```xml
   		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-api</artifactId>
			<version>0.11.5</version>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-impl</artifactId>
			<version>0.11.5</version>
			<scope>runtime</scope>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-jackson</artifactId> 
			<version>0.11.5</version>
			<scope>runtime</scope>
		</dependency>
   ```

2. Többé nem akarjuk, hogy JSESSIONID-t generáljon a keretrendszer, ezért módosítanunk kell a `SecurityConfig`-on:
    - a szűrőlánc első beállítását (`.securityContext(...)`) cseréljük le erre:
   ```java
   .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
   ```
   Ezt követően már nekünk kell gondoskodni a session felépítéséről.
3. A CORS beállításot ki kell egészíteni egy sorral, mivel a generált tokent el kell juttasuk a frontendre, amit a
   response headerben "authorization" néven fogunk megtenni.
   Mivel ezzel a lépéssel felfedjük a headert a böngésző előtt, így explicit módon tudatni kell vele, hogy headert
   küldünk, különben nem fogja elfogadni azt. Ennek beállítása viszont igencsak egyszerű:
    - A `config.setAllowHeaders(...)` beállítást követő sorba illeszük be
      ezt: `config.setExposedHeaders(Arrays.asList("Authorization"));`
    - _megj.: CSRF token esetében azért nem volt szükség erre a lépésre, mert az a keretrendszer által generált token,
      amit a böngésző külön beállítás nélkül is képes fogadni- Minden egyéni header esetében ez a lépés szükésges._

4. Hozz létre egy szűrőt (`JWTTokenGeneratorFilter`), ami implementálja a `OncePerRequestFilter` interfészt!
5. Hozz létre egy új interfészt, amiben konstansként tárolod a headert és a jwt kulcsot!
    - Éles környezetben a kulcsot biztonságosan tároljuk és nem a kódban. Ideális esetben a DevOps csapat gondoskodik
      róla, hogy CI/CD eszközökkel környezeti változóként injektálják az alkalmazásba a kitelepíts során.
   ```java
   public interface SecurityConstants {
   
       public static final String JWT_KEY = "jxgEQeXHuPq8VdbyYFNkANdudQ53YUn4";
       public static final String JWT_HEADER = "Authorization";
   
   }
   ```
6. A `JWTTokenGeneratorFilter` osztály `doFilterInternal()` metódusán belül
    - Kérd ki a `SecurityContextHolder`-től az `Authentication` objektumot!
    - Ha az nem null, akkor:
        - hozz létre egy `SecretKey` típusú kulcsot,
        - hozz létre egy String típusú jwt tokent a `Jwts` builderével.
            - Ne felejtsd el aláírni a tokent a létrehozott kulccsal!
              Amikor a `claim()` részt állítod be, akkor tulajdonképpen a token payload-ját hozod létre. Ide bármit
              betehetsz, de **ne feledkezz meg róla, hogy a tokennek ez a része csupán kódolt, nem titkosított, így ezt
              bárki könnyedén visszafejtheti!**
        - állítsd be a válasz header-ét

    - Alkoss láncot, amit majd beépíthetünk a `SecurityFilterChain`-be
   ```java
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (null != authentication) {
            SecretKey key = Keys.hmacShaKeyFor(SecurityConstants.JWT_KEY.getBytes(StandardCharsets.UTF_8));
            String jwt = Jwts.builder().setIssuer("Eazy Bank").setSubject("JWT Token")
                    .claim("username", authentication.getName())
                    .claim("authorities", populateAuthorities(authentication.getAuthorities()))
                    .setIssuedAt(new Date())
                    .setExpiration(new Date((new Date()).getTime() + 30000000))
                    .signWith(key).compact();
            response.setHeader(SecurityConstants.JWT_HEADER, jwt);
        }

        filterChain.doFilter(request, response);
    }
   ```

   A `populateAuthorities()` metódus gondoskodik arról, hogy kiolvassa a felhasználó jogosultságait és beírja a token
   payload mezőjébe

   ```java
    private String populateAuthorities(Collection<? extends GrantedAuthority> collection) {
        Set<String> authoritiesSet = new HashSet<>();
        for (GrantedAuthority authority : collection) {
            authoritiesSet.add(authority.getAuthority());
        }
        return String.join(",", authoritiesSet);
    }
   ```

7. Ezt a filtert kizárólag akkor szeretnénk alkalmazni, amikor a felhasználó bejelentkezik. Máskülönben minden egyes
   kérésnél újra és újra lezajlana a token generálásának folyamata.
   Ahhoz hogy ezt elérjük, szükségünk lesz egy másik felülírt metódusra, a `shouldNotFilter()`-re, aminek keretein belül
   meghatározhatjuk, hogy mely kérések esetén ne fusson le ez a szűrő.
   Itt ahelyett, hogy felsorolnánk a végpontjaink sokaságát, egy dupla tagadással érjük el a kívánt eredményt: Ha a
   kérés nem a `/user` végpontról érkezik, akkor ne fusson le a szűrő

   ```java
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getServletPath().equals("/user");
    }
   ```

8. Miután elkészítettük az egyedi szűrőnket, gondoskodjunk róla, hogy bekerüljön a szűrőláncba! Ezt a szűrőt akkor
   szeretnénk alkalmazni, ha a felhasználó sikeresen bejelntkezett, tehát a megfelelő metódus
   az `.addFilterAfter(new JWTTokenGeneratorFilter(), BasicAuthenticationFilter.class))`

```java
import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

public class JWTTokenGeneratorFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (null != authentication) {
            SecretKey key = Keys.hmacShaKeyFor(SecurityConstants.JWT_KEY.getBytes(StandardCharsets.UTF_8));
            String jwt = Jwts.builder().setIssuer("Eazy Bank").setSubject("JWT Token")
                    .claim("username", authentication.getName())
                    .claim("authorities", populateAuthorities(authentication.getAuthorities()))
                    .setIssuedAt(new Date())
                    .setExpiration(new Date((new Date()).getTime() + 30000000))
                    .signWith(key).compact();
            response.setHeader(SecurityConstants.JWT_HEADER, jwt);
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getServletPath().equals("/user");
    }

    private String populateAuthorities(Collection<? extends GrantedAuthority> collection) {
        Set<String> authoritiesSet = new HashSet<>();
        for (GrantedAuthority authority : collection) {
            authoritiesSet.add(authority.getAuthority());
        }
        return String.join(",", authoritiesSet);
    }

}

   ```

9. Hozz létre egy újabb egyéni szűrőt a token validálásához!
    - A `doFilterInternal()` metódussal kinyerjük a tokent a header-ből.
    - Ha az értéke nem null, akkor `try` ágon:
        - létrehozunk a generálással megegyező módon egy `SecretKey`-t
        - felépítjük a `Claims`-t a `JwtsParserBuilder()` metóduslánccal, aminek a `.parseClaimsJws(jwt)` része
          automatikusan vizsgálja a token hitelességét, **ha a láncban a kulcs is jelen van**. Probléma esetén valmilyen
          exceptiont dob:
            - ExpiredJwtException,
            - UnsupportedJwtException,
            - MalformedJwtException, SignatureException,
            - IllegalArgumentException
        - A claimsből kinyerjük a felhasználónevet és a jogosultságokat, ami alapján létrehozzuk
          a `UsernamePasswordAuthenticationToken`-t
            - Ügyelj rá, hogy a jelszó értéke `null` legyen (fölöslegesen nem utaztatjuk az érzékeny adatot)!
        - Ezután tudatni kell a Springgel, hogy egyedi módon ellenőriztük a bejelentkezést, ami sikeres volt. Ehhez
          az `Authentication` objektumot be kell állítani a `SecurityContextHolder`-ben
    - Mindez ha hibára futott volna, akkor dobunk egy `BadCredentialsException`-t
    - Végül gondoskodunk a szűrőlánc beépíthetőségéről.

```java
    @Override
protected void doFilterInternal(HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain)throws ServletException,IOException{
        String jwt=request.getHeader(SecurityConstants.JWT_HEADER);
        if(jwt!=null){
        try{
        SecretKey key=Keys.hmacShaKeyFor(SecurityConstants.JWT_KEY.getBytes(StandardCharsets.UTF_8));
        Claims claims=Jwts.parserBuilder()
        .setSigningKey(key)
        .build()
        .parseClaimsJws(jwt)
        .getBody();
        String username=String.valueOf(claims.get("username"));
        String authorities=String.valueOf(claims.get("authorities"));
        Authentication auth=new UsernamePasswordAuthenticationToken(username,
        null,
        AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
        SecurityContextHolder.getContext().setAuthentication(auth);
        }catch(Exception e){
        throw new BadCredentialsException("Invalid Token Received!");
        }
        }
        filterChain.doFilter(request,response);
        }

   ```

10. Ezt a szűrőt minden egyes kérésnél szeretnénk futtatni, egy kivételével: bejelntkezéskor ugyanis szükségtelen az
    érvényesítés, hiszen a bejelentkezés során a felhasználó kap egy új, érvényes tokent.

```java
    @Override
protected boolean shouldNotFilter(HttpServletRequest request)throws ServletException{
        return request.getServletPath().equals("/user");
        }
   ```

11. A szűrő használatához be kell azt építeni a szűrőláncba. Ezt a szűrőt bejelentkezés előtt szeretnénk használni, ezért a következő sort kell hozzáadni a lánchoz: `.addFilterBefore(new JWTTokenValidatorFilter(), BasicAuthenticationFilter.class)`
12. Ahhoz, hogy használhassuk a tokent, a frontendünknek is meg kell értenie, hogy miről van szó.
    - `login.component.ts`: Olvasd ki a fejlécből az autorizációt, és állítsd be a `sessionStorage`-be. Ehhez add hozzá ezt a sort: `window.sessionStorage.setItem("Authorization",responseData.headers.get('Authorization')!);`
    - Az interceptorban már beállítottunk egy "Basic" bejelentkezés során használt headert, most `else` ágon állítsunk be egy headert arra az esetre, ha a felhasználó `sessionStorage`-ében megtalálható az "Authorization" kulcs
    ```java
    if(this.user && this.user.password && this.user.email){
      httpHeaders = httpHeaders.append('Authorization', 'Basic ' + window.btoa(this.user.email + ':' + this.user.password));
    } else {
      let authorization = sessionStorage.getItem('Authorization');
      if (authorization){
        httpHeaders = httpHeaders.append('Authorization', authorization);
      }
    }

    ```


Ellenőrizheted a változtatásiankat azáltal, hogy megpróbálsz bejelentkeznia egy bőngészőből, ami nem tárol az alkalmazáshoz tartozó sütiket.
Nyisd meg az Application fület és bejelentkezés után csupán egy XSRF-TOKEN lesz látható, mivel a JSESSIONID létrehozását megszüntettük.
A JWT tokent a kérés fejlécében tároljuk el, amit a "Network" fülön ellenőrizhetsz. Kattints az xhr típusú user kérésre,
hogy megjelenítsd a hozzá tartozó részleteket és máris láthatod az "Authorization" kulcshoz tartozó értéket, ami maga a JWT token.
Másold ki a token értékét, és illeszd be a www.jwt.io oldal "Encoded" mezőjébe. Eredméynül jobboldalt láthatod a dekódolt tokent, amiből kiolvashatóak a belekódolt információk.
**Ezért is volt nagyon fontos, hogy a jelszót `null`-ra állítsuk a tokenben**


Bejelentkezés után maradj a "Network" fülön, és kattints az egyik opcióra, majd ellenőrizd az xhr típusú kéréshez tartozó fejlécet.
Itt is meg fogod találni a JWT tokent.


Most pedig menj az "Application" fülre, és keresd meg a "Session Storage"-et! Módosíts akár csak egy karaktert is az "Authorization" kulcshoz tartozó értéken, majd próbálj elérni egy opciót.
Az eredmény: 401


Amiket elértünk ezzel a lépéssel:
    - a felhasználó kényelmesen böngészheti az oldalunkat, anélkül hogy többször be kéne jelentkeznie
    - megvédjük a felhasználót a CSRF támadások ellen
    - nem sütiben tároljuk a bejelntkezési adatokat
    - a felhasználó jelszavát egyetlen egyszer utaztatjuk (bejelntkezés)
    - tovább fokozzuk a biztonságot azzal, hogy nem tároljuk a tokent, hanem az aláírás segítségével győződünk meg a hitelességéről
    - növeltük az oldal sebességét azáltal, hogy autentikációról és autorizációról a biztonsági szűrőlánc gondoskodik.
    - ha a token korrumpálódott, a felhasználónak nem kell jelszót változtatni, csupán újra bejelentkeznie.


### 10.lépés - Metódus szintű biztonság
A projekt jelenlegi állapotában megvalósítottunk eg lehetséges biztonsági rendszert, ami kiszolgálja a beazonosítást, és gondoskodik az egyes végpontok
valamint az onnan indított kérések hozzáférhetőségéről. Tovább fokozhatjuk a biztonságot azáltal, hogy levédjük a metódusainket is. Amikor levédünk egy
metódust, akkor olyan védelmet alakítunk ki, ami nem csupán REST kérréseken alapul.
Kétféle eszközt használhatunk:
- a felhasználó jogosultságai alapján validáljuk, hogy lehet-e hozzáférése a metódushoz, vagy sem. 
- validáljuk, hogy a metódus milyen adatot kaphat a paraméterein keresztül, és mit kaphat vissza eredményül a hívó.


Kövesd az alábbi leírást, hogy megértsd milyen módokon lehet használni:
1. Alapértelmezetten ezek a lehetőségek ki vannak kapcsolva, de az alkalmazásunkra használt `@EnableMethodSecurity` annotációval engedélyezni lehet a használatukat.
2. Engedélyezést követően konfigurálni kell. Ha hozzá szeretnénk férni a teljes eszköztárhoz, akkor az alábbi beállítást kell elvégeznünk:
    - `@EnableMethodSecurity(prePostEnabled =true, securedEnabled = true, jsr250Enabled=true)`
3. A szűrőláncban állítsd át a `/loans` ponthoz tartozó requestMatchers-t `hasRole()` helyett `authenticated()`-re (így jogosultságtól függetlenül bármely bejelentkezett felhasználó hozzáférhet)
4. A `LoanRepository` megírt metódusa felé tedd ki a `@PreAuthorize("hasRole('ROOT')")` annotációt
    - Bonyolultabb logika esetén: `PermissionEvaulator hasPermission()`
     - Nem létezik ROOT jogosultság az adatbázisunkban, így ez a metódus elérhetetlenné válik
    - Jelentkezz be a alkalmazásba, majd próbáld elérni a "Loans" menüpontot
    - Ha megnyitod a konzolt, láthatod, hogy a kérést 403-as kóddal elutasították.
    - Ha a ROOT-ot átírod USER-re, akkor már újra elérhető lesz minden bejelentkezett és "USER" jogosultsággal rendelkező felhasználó számára
    - Töröld ki az annotáción paraméterét, majd nyiss újra idézőjelt a zárójelen belül. A zárójelek között ha nyomsz egy `Ctrl+Space`-t
        azzal előhívod a javaslatokatt. Kezdd el írni, hogy "has" és láthatod, hogy milyen feltételekre lehet szűrni. 
5. Törölheted a repository metódusa feletti annotációt, mert egy másik módszert is megnézünk. Csupán annyit kell tenni,
    hogy a `LoansController getLoanDetails()` metódusát annotáljuk ezzel: `@PostAuthorize("hasRole('ROOT')")`.
    - Tegyél egy breakpointot a metódusra, és indítsd el debug módban a programot.
    - Jelentkezz be az alkalmazásba és próbáld elérni a "Loans" menüpontot.
    - A futás szünetel a breakpointon, ha tovább lépteted, akkor láthatod, hogy gond nélkül lefut,
      de a böngésző konzolát megnyitva azt is láthatod, hogy 403-as kóddal újra elutasították a kérést és nem kapod meg az adatot.
    - Tehát: a keretrendszer hagyta, hogy lefusson a metódus, de az eredmény helyett 403-ast dobott.

6. Vegyünk egy olan példát, hogy nem szeretnénk elfogadni olyan adatot a "Contact" űrlapon, ahol a név mező értéke "Test"
    - A `ContactController saveContactInqueryDetails()` metódusa felett használd ezt az annotációt: `@PreFilter("filterObject.contactName != 'Test'")`
    - Fontos tudni, hogy a `@PreFilter` és a `@PostFilter` is "collection"-t kezel, ezért használatához meg kell változtatni a metódus logikáját
        
    ```java
   @PretFilter("filterObject.contactName != 'Test'")
   public List<Contact> saveContactInquiryDetails(@RequestBody List<Contact> contacts) {
        Contact contact = contacts.get(0);
        contact.setContactId(getServiceReqNumber());
        contact.setCreateDt(new Date(System.currentTimeMillis()));
        contact = contactRepository.save(contact);
        List<Contact> returnContacts = new ArrayList<>();
        returnContacts.add(contact);
        return returnContacts;
   }
      ```
   
   És ne feledkezzünk meg róla, hogy frontenről is listát kell küldeni, ezért a `dashboard.service.ts` fájlban módosítsuk az alábbira a vonatkozó metódust:
    ```typescript
     saveMessage(contact : Contact){
        const contacts = [];
        contacts.push(contact)
        return this.http.post(environment.rooturl + AppConstants.CONTACT_API_URL,contacts,{ observe: 'response'});
    }
    ```
   
    Majd a `contact.component.ts` fájlba vegyünk fel egy új fieldet `contacts = new Array()` és módosítsuk a vonatkozó metódust az alábbire:
    ```typescript
     saveMessage(contactForm: NgForm) {
    this.dashboardService.saveMessage(this.model).subscribe(
      responseData => {
        this.contacts = <any> responseData.body;
        this.contacts.forEach(function (this: ContactComponent, contact: Contact) {
          this.model = contact;
        }.bind(this));
        contactForm.resetForm();
      });
    }
   ```

Ha most megpróbáljuk "Test" névvel küldeni az űrlapot, akkor 401-es hibát fogunk kapni, és az adat nem kerül be az adatbázisba.


### 11.lépés - OAuth2 és OpenID
Képzeljük el, hogy van egy harmadik féltől származó alkalmazás, ami a facebook oldalunkról gyűjten hasznos információkat számunkra.
Shhoz hogy ezt megtehesse be kell jelentkezzen a mi nevünkben. Korábban ez csak úgy lett volna megoldható, ha átadtuk volna a bejelentkezési 
adatainkat, de ezzel az app felhatalmazást kapott volna arra, hogy bármit megtehessen, a nevünkben amit mi is megtehetnénk.
Ezt a problémát ki lehet küszöbölni.
