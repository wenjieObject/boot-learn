package com.wenjie.mesplugin.pojo;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Id;
import javax.persistence.GeneratedValue;
import java.io.Serializable;
import java.util.Date;

/**
 * @Description  
 * @Author  linmengmeng
 * @Date 2020-08-19 13:18:52 
 */

@Entity
@Table ( name ="PAGE_BAS" , schema = "")
public class PageBas  implements Serializable {

	private static final long serialVersionUID =  686528628899478784L;

	/**
	 * 主键
	 */
   	@Column(name = "GUID" )
	@Id
	private String guid;

	/**
	 * 页面代号
	 */
   	@Column(name = "PAGE_NO" )
	private String pageNo;

	/**
	 * 页面名称
	 */
   	@Column(name = "PAGE_NAME" )
	private String pageName;

	/**
	 * 路由名称
	 */
   	@Column(name = "PAGE_PATH" )
	private String pagePath;

	/**
	 * 模组
	 */
   	@Column(name = "PAGE_MODULE_GUID" )
	private String pageModuleGuid;

	/**
	 * 后续页面
	 */
   	@Column(name = "PAGE_NXET_GUID" )
	private String pageNxetGuid;

	/**
	 * 工厂
	 */
   	@Column(name = "FACTORY" )
	private String factory;

	/**
	 * 创建者
	 */
   	@Column(name = "CREATOR" )
	private String creator;

	/**
	 * 创建时间
	 */
   	@Column(name = "CREATE_TIME" )
	private Date createTime;

	/**
	 * 修改者
	 */
   	@Column(name = "MODIFIER" )
	private String modifier;

	/**
	 * 修改时间
	 */
   	@Column(name = "MODIFY_TIME" )
	private Date modifyTime;

	/**
	 * 标志位
	 */
   	@Column(name = "FLAG" )
	private String flag;

	/**
	 * 删除标志位
	 */
   	@Column(name = "DELETE_FLAG" )
	private String deleteFlag;

   	@Column(name = "PAGE_ORDER" )
	private String pageOrder;

   	@Column(name = "PAGE_TYPE" )
	private String pageType;

   	@Column(name = "PAGE_ICON" )
	private String pageIcon;

	public String getGuid() {
		return this.guid;
	}

	public void setGuid(String guid) {
		this.guid = guid;
	}

	public String getPageNo() {
		return this.pageNo;
	}

	public void setPageNo(String pageNo) {
		this.pageNo = pageNo;
	}

	public String getPageName() {
		return this.pageName;
	}

	public void setPageName(String pageName) {
		this.pageName = pageName;
	}

	public String getPagePath() {
		return this.pagePath;
	}

	public void setPagePath(String pagePath) {
		this.pagePath = pagePath;
	}

	public String getPageModuleGuid() {
		return this.pageModuleGuid;
	}

	public void setPageModuleGuid(String pageModuleGuid) {
		this.pageModuleGuid = pageModuleGuid;
	}

	public String getPageNxetGuid() {
		return this.pageNxetGuid;
	}

	public void setPageNxetGuid(String pageNxetGuid) {
		this.pageNxetGuid = pageNxetGuid;
	}

	public String getFactory() {
		return this.factory;
	}

	public void setFactory(String factory) {
		this.factory = factory;
	}

	public String getCreator() {
		return this.creator;
	}

	public void setCreator(String creator) {
		this.creator = creator;
	}

	public Date getCreateTime() {
		return this.createTime;
	}

	public void setCreateTime(Date createTime) {
		this.createTime = createTime;
	}

	public String getModifier() {
		return this.modifier;
	}

	public void setModifier(String modifier) {
		this.modifier = modifier;
	}

	public Date getModifyTime() {
		return this.modifyTime;
	}

	public void setModifyTime(Date modifyTime) {
		this.modifyTime = modifyTime;
	}

	public String getFlag() {
		return this.flag;
	}

	public void setFlag(String flag) {
		this.flag = flag;
	}

	public String getDeleteFlag() {
		return this.deleteFlag;
	}

	public void setDeleteFlag(String deleteFlag) {
		this.deleteFlag = deleteFlag;
	}

	public String getPageOrder() {
		return this.pageOrder;
	}

	public void setPageOrder(String pageOrder) {
		this.pageOrder = pageOrder;
	}

	public String getPageType() {
		return this.pageType;
	}

	public void setPageType(String pageType) {
		this.pageType = pageType;
	}

	public String getPageIcon() {
		return this.pageIcon;
	}

	public void setPageIcon(String pageIcon) {
		this.pageIcon = pageIcon;
	}

	@Override
	public String toString() {
		return "{" +
					"guid='" + guid + '\'' +
					"pageNo='" + pageNo + '\'' +
					"pageName='" + pageName + '\'' +
					"pagePath='" + pagePath + '\'' +
					"pageModuleGuid='" + pageModuleGuid + '\'' +
					"pageNxetGuid='" + pageNxetGuid + '\'' +
					"factory='" + factory + '\'' +
					"creator='" + creator + '\'' +
					"createTime='" + createTime + '\'' +
					"modifier='" + modifier + '\'' +
					"modifyTime='" + modifyTime + '\'' +
					"flag='" + flag + '\'' +
					"deleteFlag='" + deleteFlag + '\'' +
					"pageOrder='" + pageOrder + '\'' +
					"pageType='" + pageType + '\'' +
					"pageIcon='" + pageIcon + '\'' +
				'}';
	}

}
