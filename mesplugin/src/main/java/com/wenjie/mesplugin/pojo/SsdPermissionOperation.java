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
 * @Date 2020-08-19 13:21:49 
 */

@Entity
@Table ( name ="SSD_PERMISSION_OPERATION" , schema = "")
public class SsdPermissionOperation  implements Serializable {

	private static final long serialVersionUID =  3719684569453195469L;

	/**
	 * 主键
	 */
   	@Column(name = "GUID" )
	@Id
	private String guid;

	/**
	 * 权限guid
	 */
   	@Column(name = "PAGE_GUID" )
	private String pageGuid;

	/**
	 * 操作guid
	 */
   	@Column(name = "OPERATION_GUID" )
	private String operationGuid;

	/**
	 * 创建人
	 */
   	@Column(name = "CREATOR" )
	private String creator;

	/**
	 * 创建时间
	 */
   	@Column(name = "CREATE_TIME" )
	private Date createTime;

	/**
	 * 修改人
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
	 * 是否有效
	 */
   	@Column(name = "DELETE_FLAG" )
	private String deleteFlag;

	/**
	 * 工厂
	 */
   	@Column(name = "FACTORY" )
	private String factory;

   	@Column(name = "PERMISSION_GUID" )
	private String permissionGuid;

	public String getGuid() {
		return this.guid;
	}

	public void setGuid(String guid) {
		this.guid = guid;
	}

	public String getPageGuid() {
		return this.pageGuid;
	}

	public void setPageGuid(String pageGuid) {
		this.pageGuid = pageGuid;
	}

	public String getOperationGuid() {
		return this.operationGuid;
	}

	public void setOperationGuid(String operationGuid) {
		this.operationGuid = operationGuid;
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

	public String getFactory() {
		return this.factory;
	}

	public void setFactory(String factory) {
		this.factory = factory;
	}

	public String getPermissionGuid() {
		return this.permissionGuid;
	}

	public void setPermissionGuid(String permissionGuid) {
		this.permissionGuid = permissionGuid;
	}

	@Override
	public String toString() {
		return "{" +
					"guid='" + guid + '\'' +
					"pageGuid='" + pageGuid + '\'' +
					"operationGuid='" + operationGuid + '\'' +
					"creator='" + creator + '\'' +
					"createTime='" + createTime + '\'' +
					"modifier='" + modifier + '\'' +
					"modifyTime='" + modifyTime + '\'' +
					"flag='" + flag + '\'' +
					"deleteFlag='" + deleteFlag + '\'' +
					"factory='" + factory + '\'' +
					"permissionGuid='" + permissionGuid + '\'' +
				'}';
	}

}
