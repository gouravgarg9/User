const includes = (arr,key)=>
{
    if(arr.indexOf(key) == -1)
        return false;
    return true;
}

module.exports = (obj, changeObj, ...fields) => {
  const applicableFieldsObj = {};
  for (const key in obj) {
    if (includes(fields, key)) applicableFieldsObj[`${key}`] = obj[`${key}`];
    else if (changeObj) delete obj[`${key}`];
  }
  return applicableFieldsObj;
};
