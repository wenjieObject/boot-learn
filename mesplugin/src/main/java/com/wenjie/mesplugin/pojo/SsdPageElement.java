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
 * @Date 2020-08-19 13:20:41 
 */

@Entity
@Table ( name ="SSD_PAGE_ELEMENT" , schema = "")
public class SsdPageElement  implements Serializable {

	private static final long serialVersionUID =  2168007989248466513L;

	/**
	 * 主键
	 */
   	@Column(name = "GUID" )
	@Id
	private String guid;

	/**
	 * 控制代号
	 */
   	@Column(name = "OPERATION_CODE" )
	private String operationCode;

	/**
	 * 控制名称
	 */
   	@Column(name = "OPERATION_NAME" )
	private String operationName;

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

   	@Column(name = "ELEMENT_ORDER" )
	private String elementOrder;

	public String getGuid() {
		return this.guid;
	}

	public void setGuid(String guid) {
		this.guid = guid;
	}

	public String getOperationCode() {
		return this.operationCode;
	}

	public void setOperationCode(String operationCode) {
		this.operationCode = operationCode;
	}

	public String getOperationName() {
		return this.operationName;
	}

	public void setOperationName(String operationName) {
		this.operationName = operationName;
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

	public String getElementOrder() {
		return this.elementOrder;
	}

	public void setElementOrder(String elementOrder) {
		this.elementOrder = elementOrder;
	}

	@Override
	public String toString() {
		return "{" +
					"guid='" + guid + '\'' +
					"operationCode='" + operationCode + '\'' +
					"operationName='" + operationName + '\'' +
					"creator='" + creator + '\'' +
					"createTime='" + createTime + '\'' +
					"modifier='" + modifier + '\'' +
					"modifyTime='" + modifyTime + '\'' +
					"flag='" + flag + '\'' +
					"deleteFlag='" + deleteFlag + '\'' +
					"factory='" + factory + '\'' +
					"elementOrder='" + elementOrder + '\'' +
				'}';
	}

}
