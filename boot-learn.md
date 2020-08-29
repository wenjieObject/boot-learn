```html
http://blog.didispace.com/spring-boot-learning-2x/
```

## 1.连接oracle，jpa操作数据库

### 1.1引入pom

```xml
       <!--  操作数据库jpa-->
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-data-jpa</artifactId>
		</dependency>

        <!-- mysql 驱动 -->
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
        </dependency>   

		<!-- oracle数据库jar包-->
		<dependency>
			<groupId>com.oracle</groupId>
			<artifactId>ojdbc6</artifactId>
			<version>11.2.0.3</version>
		</dependency>
```

### 1.2在配置文件中application.properties，导入数据库配置

**注意spring.jpa.hibernate.ddl-auto**

```properties
spring.jpa.database=oracle
spring.jpa.show-sql=true
spring.jpa.hibernate.ddl-auto=update

spring.datasource.driver-class-name=oracle.jdbc.driver.OracleDriver
spring.datasource.url= jdbc:oracle:thin:@10.40.3.209:1522:orcl 
spring.datasource.username=DigiwinMES_Test
spring.datasource.password=Digiwin1982
```



### 1.3按照数据库的字段映射model

@Entity表示这是一张表

@Id主键

@Column字段

```java

@Entity
public class SSD_PERMISSION_OPERATIONS {

    @Id
    private  String GUID;

    @Column
    private String PAGE_GUID;
    @Column
    private String OPERATION_GUID;
    @Column
    private String CREATOR;
```

### 1.4继承JpaRepository接口

JpaRepository<SSD_PERMISSION_OPERATIONS,String> 、

SSD_PERMISSION_OPERATIONS是表模型

String 主键类型

```java
public interface OperationRepository extends JpaRepository<SSD_PERMISSION_OPERATIONS,String> {
}
```



### 1.5 使用

```java
@Autowired
	OperationRepository operationRepository;

	@Test
	void contextLoads() {
		List<SSD_PERMISSION_OPERATIONS> operations = operationRepository.findAll();

		for (SSD_PERMISSION_OPERATIONS operation:operations
			 ) {

			System.out.println(operation.toString());
		}

	}
```



## 2. Jpa代码生成



### 2.1 idea连接数据库

菜单栏 ----view---tool windows----database --添加数据库 ---data source--- 选择数据库---输入需要连接的数据库的信息，然后点击左下角的下载工具，然后点击Test Connection，如果提示Success 证明连接成功了，这时点击Apply，ok即可------选择要生成的表----右击----scripted Extensions----go to scripts  dictionary---在schema下选择---Generate POJOs.groovy

输入以下模板代码(**缺少Id注释**)



```java

import com.intellij.database.model.DasTable
import com.intellij.database.model.ObjectKind
import com.intellij.database.util.Case
import com.intellij.database.util.DasUtil

import java.text.SimpleDateFormat

/*
 * Available context bindings:
 *   SELECTION   Iterable<DasObject>
 *   PROJECT     project
 *   FILES       files helper
 */
packageName = ""
typeMapping = [
        (~/(?i)tinyint|smallint|mediumint/)      : "Integer",
        (~/(?i)int/)                             : "Long",
        (~/(?i)bool|bit/)                        : "Boolean",
        (~/(?i)float|double|decimal|real/)       : "BigDecimal",
        (~/(?i)datetime|timestamp|date|time/)    : "Date",
        (~/(?i)blob|binary|bfile|clob|raw|image/): "InputStream",
        (~/(?i)/)                                : "String"
]


FILES.chooseDirectoryAndSave("Choose directory", "Choose where to store generated files") { dir ->
  SELECTION.filter { it instanceof DasTable && it.getKind() == ObjectKind.TABLE }.each { generate(it, dir) }
}

def generate(table, dir) {
  def className = javaName(table.getName(), true)
  def fields = calcFields(table)
  packageName = getPackageName(dir)
  PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(new FileOutputStream(new File(dir, className + ".java")), "UTF-8"))
  printWriter.withPrintWriter { out -> generate(out, className, fields, table) }

//    new File(dir, className + ".java").withPrintWriter { out -> generate(out, className, fields,table) }
}

// 获取包所在文件夹路径
def getPackageName(dir) {
  return dir.toString().replaceAll("\\\\", ".").replaceAll("/", ".").replaceAll("^.*src(\\.main\\.java\\.)?", "") + ";"
}

def generate(out, className, fields, table) {
  out.println "package $packageName"
  out.println ""
  out.println "import javax.persistence.Column;"
  out.println "import javax.persistence.Entity;"
  out.println "import javax.persistence.Table;"
  out.println "import javax.persistence.Id;"
  out.println "import javax.persistence.GeneratedValue;"
  out.println "import java.io.Serializable;"
  Set types = new HashSet()

  fields.each() {
    types.add(it.type)
  }

  if (types.contains("Date")) {
    out.println "import java.util.Date;"
  }

  if (types.contains("BigDecimal")) {
    out.println "import java.math.BigDecimal;"
  }

  if (types.contains("InputStream")) {
    out.println "import java.io.InputStream;"
  }
  out.println ""
  out.println "/**\n" +
          " * @Description  \n" +
          " * @Author  linmengmeng\n" + //1. 修改idea为自己名字
          " * @Date " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()) + " \n" +
          " */"
  out.println ""
  out.println "@Entity"
  out.println "@Table ( name =\"" + table.getName() + "\" , schema = \"\")" //2. schema = \"后面添加自己的表空间名称(mysql可以不添加, 不用这个schema属性也行)
  out.println "public class $className  implements Serializable {"
  out.println ""
  out.println genSerialID()
  fields.each() {
    out.println ""
    // 输出注释
    if (isNotEmpty(it.commoent)) {
      out.println "\t/**"
      out.println "\t * ${it.commoent.toString()}"
      out.println "\t */"
    }

    if ((it.annos+"").indexOf("[@Id]") >= 0) out.println "\t@Id"

    if (it.annos != "") out.println "   ${it.annos.replace("[@Id]", "")}"


    // 输出成员变量
    out.println "\tprivate ${it.type} ${it.name};"
  }

  // 输出get/set方法
  fields.each() {
    out.println ""
    out.println "\tpublic ${it.type} get${it.name.capitalize()}() {"
    out.println "\t\treturn this.${it.name};"
    out.println "\t}"
    out.println ""

    out.println "\tpublic void set${it.name.capitalize()}(${it.type} ${it.name}) {"
    out.println "\t\tthis.${it.name} = ${it.name};"
    out.println "\t}"
  }

  // 输出toString方法
  out.println ""
  out.println "\t@Override"
  out.println "\tpublic String toString() {"
  out.println "\t\treturn \"{\" +"
  fields.each() {
    out.println "\t\t\t\t\t\"${it.name}='\" + ${it.name} + '\\'' +"
  }
  out.println "\t\t\t\t'}';"
  out.println "\t}"

  out.println ""
  out.println "}"
}

def calcFields(table) {
  DasUtil.getColumns(table).reduce([]) { fields, col ->
    def spec = Case.LOWER.apply(col.getDataType().getSpecification())

    def typeStr = typeMapping.find { p, t -> p.matcher(spec).find() }.value
    def comm = [
            colName : col.getName(),
            name    : javaName(col.getName(), false),
            type    : typeStr,
            commoent: col.getComment(),
            annos   : "\t@Column(name = \"" + col.getName() + "\" )"]
    if ("id".equals(Case.LOWER.apply(col.getName())))
      comm.annos += ["@Id"]
    fields += [comm]
  }
}

// 这里是处理数据库表前缀的方法，这里处理的是t_xxx命名的表
// 已经修改为使用javaName, 如果有需要可以在def className = javaName(table.getName(), true)中修改为javaClassName
// 处理类名（这里是因为我的表都是以t_命名的，所以需要处理去掉生成类名时的开头的T，
// 如果你不需要去掉表的前缀，那么请查找用到了 javaClassName这个方法的地方修改为 javaName 即可）
def javaClassName(str, capitalize) {
  def s = com.intellij.psi.codeStyle.NameUtil.splitNameIntoWords(str)
          .collect { Case.LOWER.apply(it).capitalize() }
          .join("")
          .replaceAll(/[^\p{javaJavaIdentifierPart}[_]]/, "_")
  // 去除开头的T  http://developer.51cto.com/art/200906/129168.htm
  s = s[1..s.size() - 1]
  capitalize || s.length() == 1 ? s : Case.LOWER.apply(s[0]) + s[1..-1]
}

def javaName(str, capitalize) {
//    def s = str.split(/(?<=[^\p{IsLetter}])/).collect { Case.LOWER.apply(it).capitalize() }
//            .join("").replaceAll(/[^\p{javaJavaIdentifierPart}]/, "_")
//    capitalize || s.length() == 1? s : Case.LOWER.apply(s[0]) + s[1..-1]
  def s = com.intellij.psi.codeStyle.NameUtil.splitNameIntoWords(str)
          .collect { Case.LOWER.apply(it).capitalize() }
          .join("")
          .replaceAll(/[^\p{javaJavaIdentifierPart}[_]]/, "_")
  capitalize || s.length() == 1 ? s : Case.LOWER.apply(s[0]) + s[1..-1]
}

def isNotEmpty(content) {
  return content != null && content.toString().trim().length() > 0
}

static String changeStyle(String str, boolean toCamel) {
  if (!str || str.size() <= 1)
    return str

  if (toCamel) {
    String r = str.toLowerCase().split('_').collect { cc -> Case.LOWER.apply(cc).capitalize() }.join('')
    return r[0].toLowerCase() + r[1..-1]
  } else {
    str = str[0].toLowerCase() + str[1..-1]
    return str.collect { cc -> ((char) cc).isUpperCase() ? '_' + cc.toLowerCase() : cc }.join('')
  }
}

//生成序列化的serialVersionUID
static String genSerialID() {
  return "\tprivate static final long serialVersionUID =  " + Math.abs(new Random().nextLong()) + "L;"
}

```



然后选择表 右击--- scripted Extensions----generage	POJOs.groovy



### 2.2 数据操作层



```java
public interface PageBasRepository  extends JpaRepository<PageBas,String> {
}

```



### 2.3 Service 层



数据操作层不需要注解

```java
@Service
public class authOperationService {

    @Autowired
    PageBasRepository pageBasRepository;

    @Autowired
    SsdPageElementRepository ssdPageElementRepository;

    @Autowired
    SsdPermissionOperationRepository ssdPermissionOperationRepository;

    public List<SsdPermissionOperation> authorizeBtn(){

        List<PageBas> pageBass= pageBasRepository.findAll();
        List<SsdPageElement> ssdPageElements= ssdPageElementRepository.findAll();

        List<SsdPermissionOperation> ssdPermissionOperations=new ArrayList<>();

        for (PageBas pageBas:pageBass) {

            for (SsdPageElement ssdPageElement: ssdPageElements) {
                SsdPermissionOperation ssdPermissionOperation=new SsdPermissionOperation();

                ssdPermissionOperation.setGuid(UUID.randomUUID().toString());
                ssdPermissionOperation.setPageGuid(pageBas.getGuid());
                ssdPermissionOperation.setOperationGuid(ssdPageElement.getGuid());
                ssdPermissionOperation.setCreator("admin");
                ssdPermissionOperation.setCreateTime(new Date());
                ssdPermissionOperation.setDeleteFlag("N");
                ssdPermissionOperation.setFactory("3000");
                ssdPermissionOperation.setPermissionGuid("9d8af325-339c-4bbe-a7fb-671490fdc5c2");

                ssdPermissionOperations.add(ssdPermissionOperation);
            }

        }

        return ssdPermissionOperationRepository.saveAll(ssdPermissionOperations);
    }
}
```



### 2.4 controller层



控制器调用服务层方法，代码生成的pojo必须有@Id注解，否则会报错

```java
@RestController
@RequestMapping("/logger")
public class loggerController {

    @Autowired
    authOperationService authOperationService;
 
    @PostMapping("/authBtn")
    public List<SsdPermissionOperation> authorizeBtn()
    {
        return authOperationService.authorizeBtn();
    }
}
```



## 3. JPA支持的方法



https://docs.spring.io/spring-data/jpa/docs/2.2.x/reference/html/#repositories.query-methods



| Keyword | Sample                       | JPQL snippet                                   |
| :------ | :--------------------------- | :--------------------------------------------- |
| `And`   | `findByLastnameAndFirstname` | `… where x.lastname = ?1 and x.firstname = ?2` |

等等。。。。



自定义sql

```java
public interface GoodsRepository extends JpaRepository<Goods, Long> {
@Query(value = "select * from goods g where g.price between :startPrice and :endPrice", nativeQuery = true)
List<Goods> findByPriceBetween(Double startPrice, Double endPrice);
}
```



### 3.1 saveAll()

原理：原生的saveAll()方法可以保证程序的正确性，但是如果数据量比较大效率低，看下源码就知道其原理是 for 循环每一条数据，然后先select一次，如果数据库存在，则update。如果不存在，则insert。

 

saveAll的源码

```java
    @Transactional
    public <S extends T> List<S> saveAll(Iterable<S> entities) {
        Assert.notNull(entities, "Entities must not be null!");
        List<S> result = new ArrayList();
        Iterator var3 = entities.iterator();

        while(var3.hasNext()) {
            S entity = var3.next();
            result.add(this.save(entity));//save方法是核心逻辑
        }

        return result;
    }
```

解决方法

**批量新增修改**

```java
  @Transactional
@Service
public class BatchService {

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * 批量插入
     *
     * @param list 实体类集合
     * @param <T>  表对应的实体类
     */
    public <T> void batchInsert(List<T> list) {
        if (!ObjectUtils.isEmpty(list)){
            for (int i = 0; i < list.size(); i++) {
                entityManager.persist(list.get(i));
                if (i % 50 == 0) {
                    entityManager.flush();
                    entityManager.clear();
                }
            }
            entityManager.flush();
            entityManager.clear();
        }
    }


    /**
     * 批量更新
     *
     * @param list 实体类集合
     * @param <T>  表对应的实体类
     */
    public <T> void batchUpdate(List<T> list) {
        if (!ObjectUtils.isEmpty(list)){
            for (int i = 0; i < list.size(); i++) {
                entityManager.merge(list.get(i));
                if (i % 50 == 0) {
                    entityManager.flush();
                    entityManager.clear();
                }
            }
            entityManager.flush();
            entityManager.clear();
        }
    }


}
```



**使用**

```java
    @Autowired
    BatchService batchService;

 batchService.batchInsert(ssdPermissionOperationList);
```





## 4. jpa问题汇总

https://www.jianshu.com/p/23e567ebcf0b



## 5.spring.jpa.hibernate.ddl-auto



## 6.springboot整合shiro

权限管理

需要5张表

用户表、角色表、权限表、用户角色表、角色权限表

### 6.1.导入坐标jar

```xml
<dependency>
   <groupId>org.springframework.boot</groupId>
   <artifactId>spring-boot-devtools</artifactId>
   <optional>true</optional>
</dependency>

<dependency>
   <groupId>org.apache.shiro</groupId>
   <artifactId>shiro-spring</artifactId>
   <version>1.4.0</version>
</dependency>
```



### 6.2.添加config文件

```java
import java.util.HashMap;
import java.util.Map;

import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ShiroConfig {
    @Bean
    public ShiroFilterFactoryBean shirFilter(SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);

        Map<String, String> filterChainDefinitionMap = new HashMap<String, String>();
        shiroFilterFactoryBean.setLoginUrl("/login");
        //shiroFilterFactoryBean.setUnauthorizedUrl("/unauthc");
        //shiroFilterFactoryBean.setSuccessUrl("/home/index");

        filterChainDefinitionMap.put("/doLogin", "anon");
        filterChainDefinitionMap.put("/**", "authc");
//        filterChainDefinitionMap.put("/authc/index", "authc");
//        filterChainDefinitionMap.put("/authc/admin", "roles[admin]");
//        filterChainDefinitionMap.put("/authc/renewable", "perms[Create,Update]");
//        filterChainDefinitionMap.put("/authc/removable", "perms[Delete]");
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return shiroFilterFactoryBean;
    }

    @Bean
    public HashedCredentialsMatcher hashedCredentialsMatcher() {
        HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
        hashedCredentialsMatcher.setHashAlgorithmName(PasswordHelper.ALGORITHM_NAME); // 散列算法
        hashedCredentialsMatcher.setHashIterations(PasswordHelper.HASH_ITERATIONS); // 散列次数
        return hashedCredentialsMatcher;
    }

    @Bean
    public EnceladusShiroRealm shiroRealm() {
        EnceladusShiroRealm shiroRealm = new EnceladusShiroRealm();
        shiroRealm.setCredentialsMatcher(hashedCredentialsMatcher()); // 原来在这里
        return shiroRealm;
    }

    @Bean
    public SecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(shiroRealm());
        return securityManager;
    }


    @Bean
    public PasswordHelper passwordHelper() {
        return new PasswordHelper();
    }

    

    // 以下三个方法主要用于注解权限控制
    @Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor(){
        return new LifecycleBeanPostProcessor();
    }

    @Bean
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator(){
        DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        defaultAdvisorAutoProxyCreator.setProxyTargetClass(true);
        return defaultAdvisorAutoProxyCreator;
    }

    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(@Autowired DefaultWebSecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;

    }

}
```



### 6.3.密码加密



```java
package com.wenjie.esblog.utils;

import com.wenjie.esblog.pojo.User;
import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.util.ByteSource;

public class PasswordHelper {
    private RandomNumberGenerator randomNumberGenerator = new SecureRandomNumberGenerator();
    public static final String ALGORITHM_NAME = "md5"; // 基础散列算法
    public static final int HASH_ITERATIONS = 2; // 自定义散列次数

    public void encryptPassword(User user) {
        // 随机字符串作为salt因子，实际参与运算的salt我们还引入其它干扰因子
        user.setSalt(randomNumberGenerator.nextBytes().toHex());
        String newPassword = new SimpleHash(ALGORITHM_NAME, user.getPassword(),
                ByteSource.Util.bytes(user.getCredentialsSalt()), HASH_ITERATIONS).toHex();
        user.setPassword(newPassword);
    }
}
```



### 6.4. 自定义realm 登录后保存session



```java
package com.wenjie.esblog.utils;

import com.wenjie.esblog.pojo.SysPermission;
import com.wenjie.esblog.pojo.SysRole;
import com.wenjie.esblog.pojo.User;
import com.wenjie.esblog.service.UserService;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;

public class EnceladusShiroRealm  extends AuthorizingRealm {

    @Autowired
    private UserService userService;

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {

        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        String username = (String) principals.getPrimaryPrincipal();

        User user = userService.findUserByName(username);

        for (SysRole role : user.getRoles()) {
            authorizationInfo.addRole(role.getRole());
            for (SysPermission permission : role.getPermissions()) {
                authorizationInfo.addStringPermission(permission.getName());
            }
        }
        return authorizationInfo;

    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String username = (String) token.getPrincipal();
        User user = userService.findUserByName(username);

        if (user == null) {
            return null;
        }
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(user.getUsername(), user.getPassword(),
                ByteSource.Util.bytes(user.getCredentialsSalt()), getName());
        return authenticationInfo;
    }
}
```



### 6.5. 使用权限控制

前后端分离的方式，未登陆跳转login，返回json串

```java
package com.wenjie.esblog.controller;

import com.wenjie.esblog.pojo.User;
import com.wenjie.esblog.service.UserService;
import com.wenjie.esblog.utils.PasswordHelper;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping
public class HomeController {

    @Autowired
    private UserService userService;
    @Autowired
    private PasswordHelper passwordHelper;

    @GetMapping("login")
    public Object login() {
        return " 《《未登陆》》 ";
    }
    
//    注解校验权限方式
//    shirFilter使用通配符校验权限
    @GetMapping("authc")
    @RequiresRoles(value={"admin","user"},logical = Logical.OR)
    public Object unauthc() {
        return "Here is authc page RequiresRoles";
    }

    @GetMapping("doLogin")
    public Object doLogin(@RequestParam String username, @RequestParam String password) {
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        Subject subject = SecurityUtils.getSubject();
        try {
            subject.login(token);
        } catch (IncorrectCredentialsException ice) {
            return "password error!";
        } catch (UnknownAccountException uae) {
            return "username error!";
        }

        User user = userService.findUserByName(username);
        subject.getSession().setAttribute("user", user);
        return "SUCCESS";
    }

    @GetMapping("register")
    public Object register(@RequestParam String username, @RequestParam String password) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(password);
        passwordHelper.encryptPassword(user);

        userService.saveUser(user);
        return "SUCCESS";
    }
}
```



## 7.后端接口统一返回值



### 7.1.实体类默认校验

lombok包可以减少写get set

```xml
<!--lombok依赖包，简化类。非必须导入-->
<dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
    <optional>true</optional>
</dependency>
```



新增User实体模型

```java
package com.wenjie.esblog.pojo;

import lombok.Data;

import java.io.Serializable;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Data
@Entity
@Table(name = "user_t")
public class User implements Serializable {
   private static final long serialVersionUID = -3320971805590503443L;
   @Id
   @GeneratedValue
   @NotNull(message = "用户id不能为空")
   private long id;

   @NotNull(message = "用户账号不能为空")
   @Size(min = 6, max = 11, message = "账号长度必须是6-11个字符")
   private String username;

   @NotNull(message = "用户密码不能为空")
   @Size(min = 6, max = 11, message = "密码长度必须是6-16个字符")
   private String password;

   private String salt;
```



### 7.2. 统一响应格式定义



```java
package com.wenjie.esblog.pojo;

import lombok.Getter;

@Getter
public class ResultVO<T> {

    /**
     * 状态码，比如1000代表响应成功
     */
    private int code;
    /**
     * 响应信息，用来说明响应情况
     */
    private String msg;
    /**
     * 响应的具体数据
     */
    private T data;

    public ResultVO(T data) {
        this(ResultCode.SUCCESS, data);
    }

    public ResultVO(ResultCode resultCode, T data) {
        this.code = resultCode.getCode();
        this.msg = resultCode.getMsg();
        this.data = data;
    }
    
}
```



### 7.3. 自定义统一响应编码



```java
package com.wenjie.esblog.pojo;

import lombok.Getter;

@Getter
public enum ResultCode {

    SUCCESS(1000, "操作成功"),

    FAILED(1001, "响应失败"),

    VALIDATE_FAILED(1002, "参数校验失败"),

    ERROR(5000, "未知错误");

    private int code;
    private String msg;

    ResultCode(int code, String msg) {
        this.code = code;
        this.msg = msg;
    }
}
```



### 7.4. 自定义统一接口异常响应格式



```java
package com.wenjie.esblog.pojo;

import lombok.Getter;

@Getter
public class APIException extends RuntimeException {

    private int code;
    private String msg;

    public APIException() {
        this(1001, "接口错误");
    }

    public APIException(String msg) {
        this(1001, msg);
    }

    public APIException(int code, String msg) {
        super(msg);
        this.code = code;
        this.msg = msg;
    }
}
```



### 7.5.自定义统一异常处理类



```java
package com.wenjie.esblog.utils;

import com.wenjie.esblog.pojo.APIException;
import com.wenjie.esblog.pojo.ResultCode;
import com.wenjie.esblog.pojo.ResultVO;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ExceptionControllerAdvice {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResultVO<String> MethodArgumentNotValidExceptionHandler(MethodArgumentNotValidException e) {
        // 从异常对象中拿到ObjectError对象
        ObjectError objectError = e.getBindingResult().getAllErrors().get(0);
        // 然后提取错误提示信息进行返回
        //return objectError.getDefaultMessage();
        // 注意哦，这里返回类型是自定义响应体
        return new ResultVO<>(ResultCode.VALIDATE_FAILED, objectError.getDefaultMessage());
    }

    @ExceptionHandler(APIException.class)
    public  ResultVO<String> APIExceptionHandler(APIException e) {
        //return e.getMsg();
        // 注意哦，这里返回类型是自定义响应体
        return new ResultVO<>(ResultCode.FAILED, e.getMsg());
    }

    @ExceptionHandler(Exception.class)
    public  ResultVO<String> ExceptionHandler(Exception e) {
        //return e.getMsg();
        // 注意哦，这里返回类型是自定义响应体
        return new ResultVO<>(ResultCode.FAILED, e.getMessage()+"通用异常数据");
    }

}
```



### 7.6.自定义统一响应处理类



```java
package com.wenjie.esblog.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wenjie.esblog.pojo.APIException;
import com.wenjie.esblog.pojo.ResultVO;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

@RestControllerAdvice(basePackages = {"com.wenjie.esblog.controller"}) // 注意哦，这里要加上需要扫描的包
public class ResponseControllerAdvice implements ResponseBodyAdvice<Object> {
    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        // false;
        // 如果接口返回的类型本身就是ResultVO那就没有必要进行额外的操作，返回false
        return !returnType.getGenericParameterType().equals(ResultVO.class);
    }

    @Override
    public Object beforeBodyWrite(Object data, MethodParameter returnType, MediaType selectedContentType, Class<? extends HttpMessageConverter<?>> selectedConverterType, ServerHttpRequest request, ServerHttpResponse response) {
        //return null;

        // String类型不能直接包装，所以要进行些特别的处理
        if (returnType.getGenericParameterType().equals(String.class)) {
            ObjectMapper objectMapper = new ObjectMapper();
            try {
                // 将数据包装在ResultVO里后，再转换为json字符串响应给前端
                return objectMapper.writeValueAsString(new ResultVO<>(data));
            } catch (JsonProcessingException e) {
                throw new APIException("返回String类型错误");
            }
        }
        // 将原本的数据包装在ResultVO里
        return new ResultVO<>(data);
    }
}
```



### 7.7.调用测试



```java
package com.wenjie.esblog.controller;

import com.wenjie.esblog.pojo.User;
import com.wenjie.esblog.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("user")
public class UserController {

    @Autowired
    private UserService userService;


    @PostMapping("/addUser")
    public String addUser(@RequestBody @Valid User user) {

         userService.saveUser(user);
         return "success";
    }

    @GetMapping("/getUser")
    public User getUser() throws Exception {
        User user = new User();
        user.setId(1L);
        user.setUsername("12345678");
        user.setPassword("12345678");
        user.setSalt("123@qq.com");

        //throw new APIException("123123");
        return  user;
        //return user;
    }

}
```





## 8.jpa配置多个数据源



```bash
├── config
│   ├── DataSourceConfig.java
│   ├── MasterConfig.java
│   ├── SlaveConfig.java
├── controller
│   ├── JpaMultidbController.java
├── master
│   ├── pojo
│   ├── ├── Student.java
│   ├── repository
│   ├── ├── StudentDao.java
├── slave
│   ├── pojo
│   ├── ├── Teacher.java
│   ├── repository
│   ├── ├── TeacherDao.java
├── MultidbApplication.java

```

### 8.1 配置文件

新建两个数据库，主数据源product，其他数据源customer

```yaml
spring:
  datasource:
    master:
      driver-class-name: com.mysql.cj.jdbc.Driver
      url: jdbc:mysql://127.0.0.1:3306/product?serverTimezone=UTC
      username: root
      password: root
    slave:
      driver-class-name: com.mysql.cj.jdbc.Driver
      url: jdbc:mysql://127.0.0.1:3306/customer?serverTimezone=UTC
      username: root
      password: root

  jpa:
    generate-ddl: true
    hibernate:
      ddl-auto: update
    show-sql: true
```

pom配置文件

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-devtools</artifactId>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
    <scope>runtime</scope>
</dependency>
```



### 8.2. 配置代码config



主配置文件代码

```java
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import javax.sql.DataSource;

@Configuration
public class DataSourceConfig {
    //master库
    @Primary
    @Bean(name = "masterDataSourceProperties")
    @Qualifier("masterDataSourceProperties")
    @ConfigurationProperties(prefix = "spring.datasource.master")
    public DataSourceProperties masterDataSourceProperties() {
        return new DataSourceProperties();
    }

    @Primary
    @Bean(name = "masterDataSource")
    @Qualifier("masterDataSource")
    @ConfigurationProperties(prefix = "spring.datasource.master")
    public DataSource masterDataSource(@Qualifier("masterDataSourceProperties") DataSourceProperties dataSourceProperties) {
        return dataSourceProperties.initializeDataSourceBuilder().build();
    }

    //slave库
    @Bean(name = "slaveDataSourceProperties")
    @Qualifier("slaveDataSourceProperties")
    @ConfigurationProperties(prefix = "spring.datasource.slave")
    public DataSourceProperties slaveDataSourceProperties() {
        return new DataSourceProperties();
    }

    @Bean(name = "slaveDataSource")
    @Qualifier("slaveDataSource")
    @ConfigurationProperties(prefix = "spring.datasource.slave")
    public DataSource slaveDataSource(@Qualifier("slaveDataSourceProperties") DataSourceProperties dataSourceProperties) {
        return dataSourceProperties.initializeDataSourceBuilder().build();
    }

}
```



--MasterConfig配置

```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateProperties;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateSettings;
import org.springframework.boot.autoconfigure.orm.jpa.JpaProperties;
import org.springframework.boot.orm.jpa.EntityManagerFactoryBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import javax.annotation.Resource;
import javax.persistence.EntityManager;
import javax.sql.DataSource;
import java.util.Map;

@Configuration
@EnableTransactionManagement
@EnableJpaRepositories(
        entityManagerFactoryRef = "masterEntityManagerFactory",
        transactionManagerRef = "masterTransactionManager",
        basePackages = {"com.wenjie.multidb.master"})
public class MasterConfig {
    @Autowired
    private HibernateProperties hibernateProperties;
    @Resource
    @Qualifier("masterDataSource")
    private DataSource masterDataSource;

    @Primary
    @Bean(name = "masterEntityManager")
    public EntityManager entityManager(EntityManagerFactoryBuilder builder) {
        return masterEntityManagerFactory(builder).getObject().createEntityManager();
    }

    @Resource
    private JpaProperties jpaProperties;


    /**
     * 设置实体类所在位置
     */
    @Primary
    @Bean(name = "masterEntityManagerFactory")
    public LocalContainerEntityManagerFactoryBean masterEntityManagerFactory(EntityManagerFactoryBuilder builder) {

        Map<String, Object> properties = hibernateProperties.determineHibernateProperties(
                jpaProperties.getProperties(), new HibernateSettings());
        return builder
                .dataSource(masterDataSource)
                .packages("com.wenjie.multidb.master")
                .persistenceUnit("masterPersistenceUnit")
                .properties(properties)
                .build();
    }

    @Primary
    @Bean(name = "masterTransactionManager")
    public PlatformTransactionManager masterTransactionManager(EntityManagerFactoryBuilder builder) {
        return new JpaTransactionManager(masterEntityManagerFactory(builder).getObject());
    }
}
```



--从配置文件SlaveConfig



```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateProperties;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateSettings;
import org.springframework.boot.autoconfigure.orm.jpa.JpaProperties;
import org.springframework.boot.orm.jpa.EntityManagerFactoryBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import javax.annotation.Resource;
import javax.persistence.EntityManager;
import javax.sql.DataSource;
import java.util.Map;


@Configuration
@EnableTransactionManagement
@EnableJpaRepositories(
        entityManagerFactoryRef = "slaveEntityManagerFactory",
        transactionManagerRef = "slaveTransactionManager",
        basePackages = {"com.wenjie.multidb.slave"})//repository的目录
public class SlaveConfig {

    @Autowired
    @Qualifier("slaveDataSource")
    private DataSource slaveDataSource;

    @Autowired
    private HibernateProperties hibernateProperties;

    @Bean(name = "slaveEntityManager")
    public EntityManager entityManager(EntityManagerFactoryBuilder builder) {
        return slaveEntityManagerFactory(builder).getObject().createEntityManager();
    }

    @Resource
    private JpaProperties jpaProperties;


    @Bean(name = "slaveEntityManagerFactory")
    public LocalContainerEntityManagerFactoryBean slaveEntityManagerFactory(EntityManagerFactoryBuilder builder) {

        Map<String, Object> properties = hibernateProperties.determineHibernateProperties(
                jpaProperties.getProperties(), new HibernateSettings());
        return builder
                .dataSource(slaveDataSource)
                .packages("com.wenjie.multidb.slave")//实体类的目录
                .persistenceUnit("slavePersistenceUnit")
                .properties(properties)
                .build();
    }

    @Bean(name = "slaveTransactionManager")
    PlatformTransactionManager slaveTransactionManager(EntityManagerFactoryBuilder builder) {
        return new JpaTransactionManager(slaveEntityManagerFactory(builder).getObject());
    }

}
```

### 8.3.DAO层代码

master是主数据库对应包，slave是多数据源对应包

pojo下写数据库实体类

repository下继承JpaRepository



```java
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity
public class Student {

    @Id
    @GeneratedValue
    private int id;

    private String name;

    private int age;

    private int grade;

    public Student() {
    }

    public Student(String name, int age, int grade) {
        this.name = name;
        this.age = age;
        this.grade = grade;
    }

    @Override
    public String toString() {
        return "Student{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", age=" + age +
                ", grade=" + grade +
                '}';
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public int getGrade() {
        return grade;
    }

    public void setGrade(int grade) {
        this.grade = grade;
    }
}
```



```java
import com.wenjie.multidb.master.pojo.Student;
import org.springframework.data.jpa.repository.JpaRepository;

public interface StudentDao extends JpaRepository<Student, Integer> {


}
```



### 8.4.控制器测试

```java
import com.wenjie.multidb.master.pojo.Student;
import com.wenjie.multidb.slave.pojo.Teacher;
import com.wenjie.multidb.slave.repository.TeacherDao;
import com.wenjie.multidb.master.repository.StudentDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JpaMultidbController {

    @Autowired
    private StudentDao studentDao;

    @Autowired
    private TeacherDao teacherDao;

    @GetMapping("/list")
    public void list() {
        System.out.println(studentDao.findAll());
        System.out.println(teacherDao.findAll());
    }

    @GetMapping("/add")
    @Transactional
    public String add(){
        Student student=new Student("name",12,0);

        studentDao.save(student);

        if(true){
            throw new RuntimeException("123321");
        }


        Teacher teacher=new Teacher("name","tt","cc");
        teacherDao.save(teacher);
        return "success";
    }

}
```