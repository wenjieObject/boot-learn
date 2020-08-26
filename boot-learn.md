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

