### 一.Spring Security登录流程

#####    1.新建MyUsernamePasswordAuthenticationFilter,继承AbstractAuthenticationProcessingFilter类

​       1)拦截/login请求.  

```java
/**
  指定拦截的路径为/login,请求类型为post
*/
public MyUsernamePasswordAuthenticationFilter() {
		super(new AntPathRequestMatcher("/login", "POST"));
	}
```

​      2)重写父类attemptAuthentication方法,获取当前token进行认证.

```java
UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
				username, password);
		
		return this.getAuthenticationManager().authenticate(authRequest);
```

#####    2.对token进行认证.

​      1)authenticate内部方法实现

```java
/**
  获取内部的providers,用来对token进行认证
*/
Iterator var8 = this.getProviders().iterator()
/**
  调用parent的authenticate方法,parent方法本身为AuthenticationManager.
  和上述一样,获取内部的providers，可只此时有两个,分别为JwtAuthenticationProvider和    DaoAuthenticationProvider,在配置类中配置,后续会讲.
*/  
result = parentResult = this.parent.authenticate(authentication)

provider.supports(toTest)   //判断是否支持当前token类型,toTest为上述传入的authRequest
    
result = provider.authenticate(authentication) //调用provider的authenticate方法
```

​      2)provider的authenticate()方法的核心实现

```java
 /**
   该方法的目的是根据username获取UserDetails对象
 */
  user = this.retrieveUser(username, (UsernamePasswordAuthenticationToken)authentication)
      
 /**
   获取对象时根据UserDetailsService来执行loadUserByUsername方法的.若想自定义获取方法,可以自定义类并继承UserDetailsService对象,并在创建Provider对象时注入该类.上述在配置类配置,后续会讲.
 */     
 UserDetails loadedUser = this.getUserDetailsService().loadUserByUsername(username)
 
/**
  如下即为重写的UserDetailsService实现类,此处获取的对象为一个默认值.
 */ 
 public class JwtUserService implements UserDetailsService{
     ....
     @Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return User.builder().username("Jack").password(passwordEncoder.encode("jack-password")).roles("USER").build();
	}
    ....
 }
```

​     3)获取到对象后,执行additionalAuthenticationChecks方法.

```java
/**
  该方法会将获取到的user对象和token对象的credentials进行比对看是否一致.
*/
this.additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken)authentication)
 /**
   比对的是token的credentials和userDetails对象的password是否一致.
*/   
String presentedPassword = authentication.getCredentials().toString()
!this.passwordEncoder.matches(presentedPassword, userDetails.getPassword())
```

​     4)验证成功后,执行successfulAuthentication(request, response, chain, authResult)方法.

```java
/**
  方法实现为调用filter的successHandler对象的onAuthenticationSuccess.该handler可自定义.
*/
this.successHandler.onAuthenticationSuccess(request, response, authResult)
```

   handler对象:   

```java
/**
  该handler对象的作用是认证成功后再请求头返回token.handler对象在Configurer中配置.
*/
public class JsonLoginSuccessHandler implements AuthenticationSuccessHandler{
	
	private JwtUserService jwtUserService;
	
	public JsonLoginSuccessHandler(JwtUserService jwtUserService) {
		this.jwtUserService = jwtUserService;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		String token = jwtUserService.saveUserLoginInfo((UserDetails)authentication.getPrincipal());
		response.setHeader("Authorization", token);
	}
	
}
```

Configurer对象:

```java
/**
  该配置类主要作用是给过滤器添加相关属性,主要有manager,handler以及制定过滤器的顺序.
*/
public class JsonLoginConfigurer<T extends JsonLoginConfigurer<T, B>, B extends HttpSecurityBuilder<B>> extends AbstractHttpConfigurer<T, B>  {

	private MyUsernamePasswordAuthenticationFilter authFilter;

	public JsonLoginConfigurer() {
		this.authFilter = new MyUsernamePasswordAuthenticationFilter();
	}
	
	@Override
	public void configure(B http) throws Exception {
		authFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
		authFilter.setAuthenticationFailureHandler(new HttpStatusLoginFailureHandler());
		authFilter.setSessionAuthenticationStrategy(new NullAuthenticatedSessionStrategy());

		MyUsernamePasswordAuthenticationFilter filter = postProcess(authFilter);
        //制定过滤器的顺序,在LogoutFilter过滤器之后.
		http.addFilterAfter(filter, LogoutFilter.class);
	}
	
	public JsonLoginConfigurer<T,B> loginSuccessHandler(AuthenticationSuccessHandler authSuccessHandler){
		authFilter.setAuthenticationSuccessHandler(authSuccessHandler);
		return this;
	}

}
```

### 二.Spring Security带token认证流程

#####    1.新建JwtAuthenticationFilter,继承OncePerRequestFilter类

```java
public class JwtAuthenticationFilter extends OncePerRequestFilter
```

​      1)指定请求头携带Authorization的请求被拦截    

```java
public JwtAuthenticationFilter() {
		this.requiresAuthenticationRequestMatcher = new RequestHeaderRequestMatcher("Authorization");
	}
```

​       2)获取token对象进行认证

```java
JwtAuthenticationToken authToken = new JwtAuthenticationToken(JWT.decode(token));
authResult = this.getAuthenticationManager().authenticate(authToken)
```

​      3)认证实现和上述大致相同,不同的是token类型不一样,provider随之不一样

```java
 /**
   token类型为JwtAuthenticationToken，provider为支持该token的类型,此次为自定义provider
 */
 result = provider.authenticate(authentication) 
```

​      自定义provider:

```java
public class JwtAuthenticationProvider implements AuthenticationProvider{
	
	private JwtUserService userService;
	
	public JwtAuthenticationProvider(JwtUserService userService) {
		this.userService = userService;
	}

 /**
   重写父类的authenticate方法,此次是对token进行有效性验证.
 */
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		DecodedJWT jwt = ((JwtAuthenticationToken)authentication).getToken();
		if(jwt.getExpiresAt().before(Calendar.getInstance().getTime()))
			throw new NonceExpiredException("Token expires");
		String username = jwt.getSubject();
		UserDetails user = userService.getUserLoginInfo(username);
		if(user == null || user.getPassword()==null)
			throw new NonceExpiredException("Token expires");
		String encryptSalt = user.getPassword();
		try {
            Algorithm algorithm = Algorithm.HMAC256(encryptSalt);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withSubject(username)
                    .build();
            verifier.verify(jwt.getToken());
        } catch (Exception e) {
            throw new BadCredentialsException("JWT token verify fail", e);
        }
		JwtAuthenticationToken token = new JwtAuthenticationToken(user, jwt, user.getAuthorities());
		return token;
	}
  /**
    重写了父类的supports方法,支持的类型为JwtAuthenticationToken
  */
	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.isAssignableFrom(JwtAuthenticationToken.class);
	}

}
```

认证完成后,执行successfulAuthentication方法.

```java
successfulAuthentication(request, response, filterChain, authResult)
/**
  方法实现如下:
*/
protected void successfulAuthentication(HttpServletRequest request,
			HttpServletResponse response, FilterChain chain, Authentication authResult) 
			throws IOException, ServletException{
		SecurityContextHolder.getContext().setAuthentication(authResult);
    //successHandler为自定义的handler
		successHandler.onAuthenticationSuccess(request, response, authResult);
	}
```

handler具体实现如下:

```java
/**
  判断是否需要刷新token,若需要则返回新的token
*/
public class JwtRefreshSuccessHandler implements AuthenticationSuccessHandler{
	
	private static final int tokenRefreshInterval = 300;  //刷新间隔5分钟
	
	private JwtUserService jwtUserService;
	
	public JwtRefreshSuccessHandler(JwtUserService jwtUserService) {
		this.jwtUserService = jwtUserService;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		DecodedJWT jwt = ((JwtAuthenticationToken)authentication).getToken();
		boolean shouldRefresh = shouldTokenRefresh(jwt.getIssuedAt());
		if(shouldRefresh) {
            String newToken = jwtUserService.saveUserLoginInfo((UserDetails)authentication.getPrincipal());
            response.setHeader("Authorization", newToken);
        }	
	}
	
	protected boolean shouldTokenRefresh(Date issueAt){
        LocalDateTime issueTime = LocalDateTime.ofInstant(issueAt.toInstant(), ZoneId.systemDefault());
        return LocalDateTime.now().minusSeconds(tokenRefreshInterval).isAfter(issueTime);
    }

}

```

以上即为token认证的大概流程.

### 三.Spring Security的web配置.

```java
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{

	@Override
    protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		        .antMatchers("/image/**").permitAll()
		        .antMatchers("/admin/**").hasAnyRole("ADMIN")
		        .antMatchers("/article/**").hasRole("USER")
		        .anyRequest().authenticated()
		        .and()
		    .csrf().disable()
		    .formLogin().disable()
		    .sessionManagement().disable()
		    .cors()
		    .and()
		    .headers().addHeaderWriter(new StaticHeadersWriter(Arrays.asList(
		    		new Header("Access-control-Allow-Origin","*"),
		    		new Header("Access-Control-Expose-Headers","Authorization"))))
		    .and()
		    .addFilterAfter(new OptionsRequestFilter(), CorsFilter.class)
		    .apply(new JsonLoginConfigurer<>()).loginSuccessHandler(jsonLoginSuccessHandler())
		    .and()
		    .apply(new JwtLoginConfigurer<>()).tokenValidSuccessHandler(jwtRefreshSuccessHandler()).permissiveRequestUrls("/logout")
		    .and()
		    .logout()
//		        .logoutUrl("/logout")   //默认就是"/logout"
		        .addLogoutHandler(tokenClearLogoutHandler())
		        .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler())
		    .and()
		    .sessionManagement().disable();
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(daoAuthenticationProvider()).authenticationProvider(jwtAuthenticationProvider());
	}
	
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
	    return super.authenticationManagerBean();
	}
	
	@Bean("jwtAuthenticationProvider")
	protected AuthenticationProvider jwtAuthenticationProvider() {
		return new JwtAuthenticationProvider(jwtUserService());
	}
	
	@Bean("daoAuthenticationProvider")
	protected AuthenticationProvider daoAuthenticationProvider() throws Exception{
		//这里会默认使用BCryptPasswordEncoder比对加密后的密码，注意要跟createUser时保持一致
		DaoAuthenticationProvider daoProvider = new DaoAuthenticationProvider();
		daoProvider.setUserDetailsService(userDetailsService());
		return daoProvider;
	}

	@Override
	protected UserDetailsService userDetailsService() {
		return new JwtUserService();
	}
	
	@Bean("jwtUserService")
	protected JwtUserService jwtUserService() {
		return new JwtUserService();
	}
	
	@Bean
	protected JsonLoginSuccessHandler jsonLoginSuccessHandler() {
		return new JsonLoginSuccessHandler(jwtUserService());
	}
	
	@Bean
	protected JwtRefreshSuccessHandler jwtRefreshSuccessHandler() {
		return new JwtRefreshSuccessHandler(jwtUserService());
	}
	
	@Bean
	protected TokenClearLogoutHandler tokenClearLogoutHandler() {
		return new TokenClearLogoutHandler(jwtUserService());
	}
	
	@Bean
	protected CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("*"));
		configuration.setAllowedMethods(Arrays.asList("GET","POST","HEAD", "OPTION"));
		configuration.setAllowedHeaders(Arrays.asList("*"));
		configuration.addExposedHeader("Authorization");
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

}

```

有关角色认证:

```java
/**
  有关登录用户的角色,在登录或token认证时返回的Authentication包含了GrantedAuthority的列表
  GrantedAuthority即为用户的角色的集合.
*/
.antMatchers("/admin/**").hasAnyRole("ADMIN")
.antMatchers("/article/**").hasRole("USER")
```

以上即为Spring Security的大致原理.